package me.braydon.antivpn.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.ClientIpResolver;
import me.braydon.antivpn.common.RateLimiter;
import me.braydon.antivpn.exception.ErrorResponses;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.APIKeyRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Responsible for requiring authentication
 * using {@link APIKey}'s on all private routes.
 *
 * @author Braydon
 */
@Configuration
@EnableWebSecurity
@Slf4j(topic = "Security")
public class WebSecurityConfig {
    /**
     * Routes that can be used without an API key.
     */
    private static final String[] PUBLIC_ROUTES = { "/error", "/amiusingavpn", "/actuator/health", "/actuator/health/**" };
    
    /**
     * The amount of requests per minute an IP can make without an API key.
     */
    private static final int ANONYMOUS_REQUESTS_PER_MINUTE = 100;
    
    /**
     * The name of the header to
     * use to check for the API key.
     */
    @Value("${auth.header:X-API-Key}")
    private String authHeader;
    
    @NonNull private final APIKeyRepository apiKeyRepository;
    @NonNull private final MetricService metrics;
    @NonNull private final ClientIpResolver clientIpResolver;
    
    /**
     * The {@link RateLimiter}s for each IP address without an API key.
     */
    @NonNull private final Map<String, AnonymousLimiter> ipRateLimiters = new ConcurrentHashMap<>();
    
    public WebSecurityConfig(@NonNull APIKeyRepository apiKeyRepository, @NonNull MetricService metrics,
                             @NonNull ClientIpResolver clientIpResolver) {
        this.apiKeyRepository = apiKeyRepository;
        this.metrics = metrics;
        this.clientIpResolver = clientIpResolver;
    }
    
    @Bean @NonNull
    public SecurityFilterChain filterChain(@NonNull HttpSecurity http) throws Exception {
        KeyFilter keyFilter = new KeyFilter();
        keyFilter.setSecurityContextRepository(new RequestAttributeSecurityContextRepository());
        keyFilter.setAuthenticationManager(authentication -> {
            APIKey apiKey = (APIKey) authentication.getCredentials();
            if (apiKey == null) { // No API key found
                throw new BadCredentialsException("Invalid API key");
            }
            if (apiKey.isBanned()) { // API key is banned
                throw new BadCredentialsException("API key is banned");
            }
            log.debug("API key '{}' was used (desc={}, uses={})", APIKey.mask(apiKey.getSecret()), apiKey.getDescription(), apiKey.getUses());
            apiKey.use(); // API key was used
            apiKeyRepository.save(apiKey); // Save the API key
            authentication.setAuthenticated(true); // Mark the session as authenticated
            return authentication;
        });
        
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(List.of("*"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "DELETE"));
        corsConfiguration.setAllowedHeaders(List.of("Content-Type", authHeader));
        
        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(cors -> cors.configurationSource(request -> corsConfiguration))
            .addFilter(keyFilter)
            .addFilterBefore(new AnonymousRateLimitFilter(), AbstractPreAuthenticatedProcessingFilter.class)
            .authorizeHttpRequests(requests -> requests
                .requestMatchers(PUBLIC_ROUTES).permitAll()
                .anyRequest().authenticated())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, ex) ->
                    ErrorResponses.write(request, response, HttpStatus.UNAUTHORIZED, "A valid API key is required in the " + authHeader + " header"))
                .accessDeniedHandler((request, response, ex) ->
                    ErrorResponses.write(request, response, HttpStatus.FORBIDDEN, "Access denied")));
        return http.build();
    }
    
    /**
     * Remove IP rate limiters after inactivity to free up memory.
     */
    @Scheduled(fixedDelay = 3L, timeUnit = TimeUnit.MINUTES)
    public void cleanupRateLimiters() {
        long cutoff = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(5L);
        ipRateLimiters.values().removeIf(limiter -> limiter.lastUsed < cutoff);
    }
    
    public final class KeyFilter extends AbstractPreAuthenticatedProcessingFilter {
        @Override
        protected String getPreAuthenticatedPrincipal(@NonNull HttpServletRequest request) {
            return request.getHeader(authHeader);
        }
        
        @Override
        protected APIKey getPreAuthenticatedCredentials(@NonNull HttpServletRequest request) {
            String principal = getPreAuthenticatedPrincipal(request); // The API key provided
            if (principal == null || principal.isBlank()) {
                return null;
            }
            long before = System.currentTimeMillis();
            try {
                return apiKeyRepository.findById(principal).orElse(null);
            } finally {
                metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                    DatabaseTracker.DatabaseType.MARIADB, System.currentTimeMillis() - before); // Metrics
            }
        }
    }
    
    /**
     * Rate limits requests that don't provide an API key, by client IP.
     */
    private final class AnonymousRateLimitFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                        @NonNull FilterChain chain) throws ServletException, IOException {
            if (request.getHeader(authHeader) == null) {
                String ip = clientIpResolver.resolve(request);
                AnonymousLimiter limiter = ipRateLimiters.computeIfAbsent(ip, key -> new AnonymousLimiter());
                limiter.lastUsed = System.currentTimeMillis();
                if (!limiter.rateLimiter.tryAcquire()) { // IP is rate limited
                    ErrorResponses.write(request, response, HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
    
    private static final class AnonymousLimiter {
        private final RateLimiter rateLimiter = new RateLimiter(ANONYMOUS_REQUESTS_PER_MINUTE, TimeUnit.MINUTES);
        private volatile long lastUsed = System.currentTimeMillis();
    }
}
