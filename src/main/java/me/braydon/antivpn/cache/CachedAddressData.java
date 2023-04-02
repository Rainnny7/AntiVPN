package me.braydon.antivpn.cache;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import me.braydon.antivpn.service.AddressService;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;

/**
 * A cache for {@link AddressService.AddressData}.
 *
 * @author Braydon
 */
@AllArgsConstructor
@Getter
@ToString
@RedisHash(value = "address", timeToLive = 60L * 30L) // 30 mins
public class CachedAddressData implements Serializable {
    /**
     * The ip address.
     */
    @Id @NonNull private final String ip;
    
    /**
     * The json representing the {@link AddressService.AddressData}..
     */
    @NonNull private final String json;
    
    /**
     * The timestamp of when this was cached.
     */
    private final long timestamp;
}