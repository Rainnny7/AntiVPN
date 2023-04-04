package me.braydon.antivpn.cache;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.address.AddressService;
import me.braydon.antivpn.model.AddressData;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.util.Set;

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
     * The data that was looked up when fetching this address.
     *
     * @see AddressService.LookupData for lookup data
     */
    private final Set<AddressService.LookupData> lookupData;
    
    /**
     * The json representing the {@link AddressData}.
     */
    @NonNull private final String json;
    
    /**
     * The timestamp of when this was cached.
     */
    private final long timestamp;
    
    /**
     * Check if this cache has lookup data.
     *
     * @return true if it has lookup data, otherwise false
     * @see #lookupData for lookup data
     */
    public boolean hasLookupData() {
        return lookupData != null;
    }
    
    /**
     * Get the cached version of
     * the given address data.
     *
     * @param addressData the address data
     * @param lookupData  the lookup data used to fetch the address data
     * @return the cached address data
     */
    @NonNull
    public static CachedAddressData asCache(@NonNull AddressData addressData, Set<AddressService.LookupData> lookupData) {
        return new CachedAddressData(
            addressData.getIp(),
            lookupData,
            AntiVPN.GSON.toJson(addressData),
            System.currentTimeMillis()
        );
    }
}