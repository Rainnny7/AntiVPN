package me.braydon.antivpn.security;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.mongodb.APIKeyRepository;
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
import java.util.List;
import java.util.Objects;
import java.util.Set;

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
public class APIKeySecurityConfig {
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
    
    @Autowired
    public APIKeySecurityConfig(@NonNull APIKeyRepository repository) {
        this.repository = repository;
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
            // Updating the API key
            apiKey.use(); // API key was used
            repository.save(apiKey); // Save the API key
            
            // Log the API key being used
            log.info(String.format("API key '%s' was used (desc=%s, uses=%s)",
                apiKey.getKey(),
                apiKey.getDescription(),
                apiKey.getUses()
            ));
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
        corsConfiguration.setAllowedMethods(List.of("GET", "POST"));
        corsConfiguration.setAllowedHeaders(List.of("Content-Type", authHeader));
        corsConfiguration.setAllowCredentials(true);
        for (String allowedOrigin : Objects.requireNonNull(corsConfiguration.getAllowedOriginPatterns())) { // Log the allowed origins
            log.info("Allowed CORS origin: {}", allowedOrigin);
        }
        http.csrf().disable() // Disable CSRF
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No sessions
            .and().authorizeRequests().antMatchers("/error").permitAll() // Permit access to /error
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
        protected Object getPreAuthenticatedPrincipal(@NonNull HttpServletRequest request) {
            return request.getHeader(authHeader);
        }
        
        @Override
        protected APIKey getPreAuthenticatedCredentials(@NonNull HttpServletRequest request) {
            String principal = (String) getPreAuthenticatedPrincipal(request); // The API key provided
            APIKey apiKey;
            if (principal != null && (apiKey = repository.findByKey(principal)) != null) { // No API key found
                return apiKey;
            }
            return null;
        }
    }
}