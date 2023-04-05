package me.braydon.antivpn.security;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.RateLimiter;
import me.braydon.antivpn.common.Tuple;
import me.braydon.antivpn.exception.RateLimitException;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.model.APIKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Responsible for requiring authentication using
 * {@link APIKey}'s on routes that match "/v{version}/**".
 *
 * @author Braydon
 */
@Configuration
@EnableWebSecurity
@Slf4j(topic = "Security")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSecurityConfig {
    /**
     * The name of the header to
     * use to check for the API key.
     */
    @Value("${auth.header}")
    private String authHeader;
    
    /**
     * The {@link APIKeyRepository} to use.
     */
    @NonNull private final APIKeyRepository repository;
    
    /**
     * The {@link MetricService} to use.
     */
    @NonNull private final MetricService metrics;
    
    /**
     * The {@link RateLimiter}s for each IP address.
     */
    private final Map<String, Tuple<RateLimiter, Long>> ipRateLimiters = new HashMap<>();
    
    @Autowired
    public WebSecurityConfig(@NonNull APIKeyRepository repository, @NonNull MetricService metrics) {
        this.repository = repository;
        this.metrics = metrics;
        
        // Remove IP rate limiters after inactivity to free up memory
        new Timer().scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                ipRateLimiters.entrySet()
                    .removeIf(entry -> System.currentTimeMillis() - entry.getValue().getRight() > TimeUnit.MINUTES.toMillis(5L));
            }
        }, TimeUnit.MINUTES.toMillis(3L), TimeUnit.MINUTES.toMillis(3L));
    }
    
    @Bean @NonNull
    public SecurityFilterChain filterChain(@NonNull HttpSecurity http) throws Exception {
        KeyFilter filter = new KeyFilter();
        filter.setAuthenticationManager(authentication -> {
            String principal = (String) authentication.getPrincipal(); // The provided API key
            APIKey apiKey = (APIKey) authentication.getCredentials();
            if (apiKey == null) { // No API key found
                throw new BadCredentialsException(String.format("Invalid API key: %s", principal));
            }
            // Log the API key being used
            log.info(String.format("API key '%s' was used (desc=%s, uses=%s)",
                apiKey.getKey(),
                apiKey.getDescription(),
                apiKey.getUses()
            ));
            // API key is banned
            if (apiKey.isBanned()) { // API key is banned
                throw new BadCredentialsException("API key is banned");
            }
            // Updating the API key
            apiKey.use(); // API key was used
            repository.save(apiKey); // Save the API key
            authentication.setAuthenticated(true); // Mark the session as authenticated
            return authentication;
        });
        // Create a default API key if none exist
        if (repository.count() == 0) {
            APIKey apiKey = APIKey.generate("First API Key", APIKey.Permission.values()); // Generate the API key
            Set<APIKey.Permission> permissions = apiKey.getPermissions(); // The permissions of the API key
            repository.save(apiKey); // Save the API key
            
            // Log the creation
            log.info("-".repeat(65));
            log.info("Default API key created: {}",
                apiKey.getKey()
            );
            if (!permissions.isEmpty()) { // Log the permissions
                log.info("Permissions ({}):", permissions.size());
                for (APIKey.Permission permission : permissions) {
                    log.info("  - {}", permission);
                }
            }
            log.info("-".repeat(65));
        }
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(List.of("*"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "DELETE"));
        corsConfiguration.setAllowedHeaders(List.of("Content-Type", authHeader));
        corsConfiguration.setAllowCredentials(true);
        for (String allowedOrigin : Objects.requireNonNull(corsConfiguration.getAllowedOriginPatterns())) { // Log the allowed origins
            log.info("Allowed CORS origin: {}", allowedOrigin);
        }
        http.csrf().disable() // Disable CSRF
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No sessions
            .and().authorizeRequests().antMatchers( // Permit access to some routes
                "/error",
                "/amiusingavpn"
            ).permitAll()
            .and() // Require authentication keys for all other routes
            .addFilter(filter)
            .authorizeRequests()
            .anyRequest()
            .authenticated() // Specific route permissions
            .and().cors().configurationSource(request -> corsConfiguration); // Enable CORS
        return http.build();
    }
    
    public final class KeyFilter extends AbstractPreAuthenticatedProcessingFilter {
        @Override
        protected String getPreAuthenticatedPrincipal(@NonNull HttpServletRequest request) {
            String header = request.getHeader(authHeader);
            if (header == null) { // No API key provided, check rate limit
                checkRatelimit(request);
            }
            return header;
        }
        
        @Override
        protected APIKey getPreAuthenticatedCredentials(@NonNull HttpServletRequest request) {
            String principal = getPreAuthenticatedPrincipal(request); // The API key provided
            APIKey apiKey = null;
            long before = System.currentTimeMillis();
            try {
                if (principal != null) { // API key provided, look it up
                    apiKey = repository.findByKey(principal);
                } else { // No API key provided, check rate limit
                    checkRatelimit(request);
                }
            } finally {
                metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                    DatabaseTracker.DatabaseType.MONGODB, System.currentTimeMillis() - before); // Metrics
            }
            return apiKey;
        }
    }
    
    /**
     * Handle rate limits for unauthorized requests.
     *
     * @param request the request to check
     * @see HttpServletRequest for request
     */
    private void checkRatelimit(@NonNull HttpServletRequest request) {
        String ip = IPUtils.getRealIp(request);
        Tuple<RateLimiter, Long> tuple = ipRateLimiters.get(ip);
        if (tuple == null) { // No rate limiter made yet
            tuple = new Tuple<>(new RateLimiter(100, TimeUnit.MINUTES), System.currentTimeMillis());
            ipRateLimiters.put(ip, tuple);
        } else { // Last used the rate limiter
            tuple.setRight(System.currentTimeMillis());
        }
        if (!tuple.getLeft().tryAcquire()) { // IP is rate limited
            throw new RateLimitException();
        }
    }
}