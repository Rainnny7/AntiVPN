package me.braydon.antivpn.config;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.APIKeyRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * Makes sure there's a fully privileged API key on start.
 * <p>
 * When {@code auth.admin-key} is set, that key is created (or updated)
 * with every permission and no rate limits. Otherwise, a random key is generated and
 * logged once, if no API keys exist yet.
 * </p>
 *
 * @author Braydon
 */
@Component
@Slf4j(topic = "API Keys")
public class APIKeyInitializer implements ApplicationRunner {
    /**
     * The description of the key managed by {@code auth.admin-key}.
     */
    public static final String ADMIN_DESCRIPTION = "Admin (auth.admin-key)";
    
    /**
     * The shortest admin key that's accepted.
     */
    public static final int MIN_ADMIN_KEY_LENGTH = 16;
    
    @NonNull private final APIKeyRepository apiKeyRepository;
    private final String adminKey;
    
    public APIKeyInitializer(@NonNull APIKeyRepository apiKeyRepository, @Value("${auth.admin-key:}") String adminKey) {
        this.apiKeyRepository = apiKeyRepository;
        this.adminKey = adminKey == null ? "" : adminKey.trim();
    }
    
    @Override
    public void run(@NonNull ApplicationArguments args) {
        if (!adminKey.isEmpty()) {
            syncAdminKey();
        } else if (apiKeyRepository.count() == 0L) {
            createDefaultKey();
        }
    }
    
    private void syncAdminKey() {
        if (adminKey.length() < MIN_ADMIN_KEY_LENGTH) {
            throw new IllegalStateException("auth.admin-key must be at least " + MIN_ADMIN_KEY_LENGTH + " characters");
        }
        // Remove the key of a previous auth.admin-key, so changing it revokes the old one
        for (APIKey previous : apiKeyRepository.findByDescription(ADMIN_DESCRIPTION)) {
            if (!previous.getSecret().equals(adminKey)) {
                apiKeyRepository.delete(previous);
                log.info("Removed the previous admin API key {}", APIKey.mask(previous.getSecret()));
            }
        }
        APIKey apiKey = apiKeyRepository.findById(adminKey).orElse(null);
        if (apiKey == null) {
            apiKey = APIKey.create(adminKey, ADMIN_DESCRIPTION, APIKey.Permission.values());
        } else {
            apiKey.setDescription(ADMIN_DESCRIPTION);
            apiKey.setPermissions(new HashSet<>(Set.of(APIKey.Permission.values())));
            apiKey.setBanned(null);
        }
        apiKey.setRateLimits(new HashMap<>()); // No limits, so it's never rate limited or banned
        apiKeyRepository.save(apiKey);
        log.info("Admin API key {} is ready with every permission and no rate limits", APIKey.mask(adminKey));
    }
    
    private void createDefaultKey() {
        APIKey apiKey = APIKey.generate(apiKeyRepository, "First API Key", APIKey.Permission.values());
        Set<APIKey.Permission> permissions = apiKey.getPermissions();
        
        // Log the creation, this is the only time the full key is logged
        log.info("-".repeat(65));
        log.info("Default API key created: {}", apiKey.getSecret());
        log.info("Permissions ({}): {}", permissions.size(), permissions);
        log.info("Set auth.admin-key to manage the admin key yourself");
        log.info("-".repeat(65));
    }
}
