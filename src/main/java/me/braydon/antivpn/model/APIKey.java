package me.braydon.antivpn.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.RateLimiter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * The API key model.
 *
 * @author Braydon
 */
@Document("apiKeys")
@AllArgsConstructor
@Getter
@ToString
@Slf4j(topic = "API Key")
public final class APIKey {
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
     * The API key.
     */
    @Id @NonNull private final String key;
    
    /**
     * The description of this API key.
     */
    @NonNull private final String description;
    
    /**
     * The rate limits for this API key.
     * <p>
     * The amount of requests this API
     * key can send per time unit.
     * </p>
     *
     * @see TimeUnit for time unit
     */
    @NonNull private final ConcurrentHashMap<TimeUnit, Integer> rateLimits;
    
    /**
     * The permissions this API key has.
     *
     * @see Permission for permissions
     */
    @NonNull private final Set<Permission> permissions;
    
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
    @NonNull private final Date creation;
    
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
        Map<TimeUnit, RateLimiter> rateLimiters = RATE_LIMITERS.getOrDefault(key, new HashMap<>());
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
                log.info("API key {} was banned for excessively exceeding the rate limit", key); // Log the ban
            }
        }
        if (modifiedRateLimiters) { // Update the rate limiters if we modified them
            if (rateLimiters.isEmpty()) { // Remove the rate limiters if they are empty
                RATE_LIMITERS.remove(key);
            } else { // Update the rate limiters
                RATE_LIMITERS.put(key, rateLimiters);
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
        for (Map.Entry<TimeUnit, RateLimiter> entry : RATE_LIMITERS.get(key).entrySet()) {
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
    public static APIKey generate(@NonNull String description, @NonNull APIKey.Permission... permissions) {
        return new APIKey(
            UUID.randomUUID().toString(),
            description,
            DEFAULT_RATE_LIMITS,
            Set.of(permissions),
            null,
            0,
            null,
            new Date()
        );
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
         * Allows modification of blacklists.
         */
        BLACKLIST_MODIFY,
        
        /**
         * Allows viewing statistics.
         */
        VIEW_STATS
    }
}