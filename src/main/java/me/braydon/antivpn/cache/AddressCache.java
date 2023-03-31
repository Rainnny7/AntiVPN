package me.braydon.antivpn.cache;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;

/**
 * A cache for player names.
 *
 * @author Braydon
 */
@RedisHash(
    value = "playerNames",
    timeToLive = 30L * 60L * 1000L // Expire in a half hour
)
@AllArgsConstructor
@Getter
public final class AddressCache implements Serializable {
    /**
     * The id of this cache.
     * <p>
     * The id is the lowercase username - doing this
     * allows the cache to still work if the user changes
     * the capitalization of their username.
     * </p>
     */
    @Id @NonNull private final String id;
    
    /**
     * The unique id of the player.
     */
    @NonNull private final String uniqueId;
    
    /**
     * The username of the player.
     */
    @NonNull private final String username;
}