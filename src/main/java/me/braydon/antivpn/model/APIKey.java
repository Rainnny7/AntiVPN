package me.braydon.antivpn.model;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.RateLimiter;
import me.braydon.antivpn.repository.APIKeyRepository;

import javax.persistence.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * The API key model.
 *
 * @author Braydon
 */
@Entity
@Table(name = "apikeys")
@Setter
@Getter
@ToString
@Slf4j(topic = "API Key")
public class APIKey {
    /**
     * The default rate limits to use.
     */
    private static final ConcurrentHashMap<TimeUnit, Integer> DEFAULT_RATE_LIMITS = new ConcurrentHashMap<>() {{
        put(TimeUnit.SECONDS, 10);
        put(TimeUnit.MINUTES, 100);
        put(TimeUnit.HOURS, 1000);
        put(TimeUnit.DAYS, 10000);
    }};
    
    /**
     * The stored rate limiters for all API keys.
     * <p>
     * This is just used internally to keep track of the
     * current amount of requests for our desired limits.
     * <p>
     * The key of this map is the identifying
     * API key, and the value is the rate limiters.
     * </p>
     *
     * @see RateLimiter for rate limiter
     */
    private static final Map<String, Map<TimeUnit, RateLimiter>> RATE_LIMITERS = Collections.synchronizedMap(new HashMap<>());
    
    /**
     * The API key secret.
     */
    @Id @NonNull private String secret;
    
    /**
     * The description of this API key.
     */
    @NonNull private String description;
    
    /**
     * The rate limits for this API key.
     * <p>
     * The amount of requests this API
     * key can send per time unit.
     * </p>
     *
     * @see TimeUnit for time unit
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "apikey_ratelimits")
    @MapKeyEnumerated(EnumType.STRING)
    @MapKeyColumn(name = "limiter_timeunit")
    @Column(name = "limiter_limit")
    @NonNull
    private Map<TimeUnit, Integer> rateLimits;
    
    /**
     * The permissions this API key has.
     *
     * @see Permission for permissions
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "apikey_permissions")
    @Enumerated(EnumType.STRING)
    @Column(name = "apikey_permission")
    @NonNull
    private Set<Permission> permissions;
    
    /**
     * Whether this API key is banned.
     */
    private Date banned;
    
    /**
     * The amount of uses this API key has.
     */
    public int uses;
    
    /**
     * The {@link Date} of when this API key was last used.
     */
    private Date lastUsed;
    
    /**
     * The {@link Date} this API key was created.
     */
    @NonNull private Date creation;
    
    /**
     * Check if this API key has
     * any of the given permissions.
     *
     * @param permissions the permissions
     * @return true if has permissions, otherwise false
     * @see Permission for permission
     */
    public boolean hasPermission(@NonNull Permission... permissions) {
        for (Permission permission : permissions) {
            if (this.permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * This API key was used.
     * <p>
     * This will increment the uses and
     * update the last used {@link Date}.
     * </p>
     */
    public void use() {
        Map<TimeUnit, RateLimiter> rateLimiters = RATE_LIMITERS.getOrDefault(secret, new HashMap<>());
        boolean modifiedRateLimiters = false; // Whether the rate limiters were modified
        
        // Update the rate limiters
        for (Map.Entry<TimeUnit, Integer> rateLimit : rateLimits.entrySet()) {
            TimeUnit timeUnit = rateLimit.getKey(); // The time unit of the limit
            int limit = rateLimit.getValue(); // The limit for the time unit
            
            RateLimiter rateLimiter = rateLimiters.get(timeUnit);
            if (rateLimiter == null) { // Create a new limiter if we don't have one
                rateLimiter = new RateLimiter(limit, timeUnit);
                rateLimiters.put(timeUnit, rateLimiter);
                modifiedRateLimiters = true;
            } else {
                if (rateLimiter.getMaxTokens() != limit) { // Updating max tokens for the limiter
                    rateLimiter.setMaxTokens(limit);
                    modifiedRateLimiters = true;
                }
            }
            // Mark the API key as banned
            if (rateLimiter.isDisabled() && !isBanned()) {
                banned = new Date(); // Set the banned date
                rateLimiters.clear(); // Clear the rate limiters to refresh them
                modifiedRateLimiters = true; // We modified the rate limiters
                log.info("API key {} was banned for excessively exceeding the rate limit", secret); // Log the ban
            }
        }
        if (modifiedRateLimiters) { // Update the rate limiters if we modified them
            if (rateLimiters.isEmpty()) { // Remove the rate limiters if they are empty
                RATE_LIMITERS.remove(secret);
            } else { // Update the rate limiters
                RATE_LIMITERS.put(secret, rateLimiters);
            }
        }
        uses++;
        lastUsed = new Date();
    }
    
    /**
     * Check if this API key is rate limited.
     *
     * @return true if limited, otherwise false
     */
    public boolean checkRateLimit() {
        for (Map.Entry<TimeUnit, RateLimiter> entry : RATE_LIMITERS.get(secret).entrySet()) {
            RateLimiter rateLimiter = entry.getValue();
            if (rateLimiter.tryAcquire()) { // We can acquire a token for this rate limiter
                continue;
            }
            return true; // Rate limit exceeded
        }
        return false;
    }
    
    /**
     * Check if this API key is banned.
     *
     * @return true if banned, otherwise false
     */
    public boolean isBanned() {
        return banned != null;
    }
    
    /**
     * Generate a new API key with
     * the given permissions.
     *
     * @param permissions the permissions
     * @return the api key
     */
    @NonNull
    public static APIKey generate(@NonNull APIKeyRepository apiKeyRepository, @NonNull String description, @NonNull Permission... permissions) {
        APIKey apiKey = new APIKey();
        apiKey.setSecret(UUID.randomUUID().toString()); // Use a random UUID as the API key
        apiKey.setDescription(description);
        apiKey.setRateLimits(DEFAULT_RATE_LIMITS);
        apiKey.setPermissions(Set.of(permissions));
        apiKey.setBanned(null);
        apiKey.setUses(0);
        apiKey.setLastUsed(null);
        apiKey.setCreation(new Date());
        return apiKeyRepository.save(apiKey);
    }
    
    public enum Permission {
        /**
         * Allows purging of the cache.
         */
        PURGE_CACHE,
        
        /**
         * Allows ignoring of the address cache.
         */
        IGNORE_ADDRESS_CACHE,
        
        /**
         * Allows management of blacklists.
         */
        MANAGE_BLACKLIST,
        
        /**
         * Allows viewing statistics.
         */
        VIEW_STATS
    }
}