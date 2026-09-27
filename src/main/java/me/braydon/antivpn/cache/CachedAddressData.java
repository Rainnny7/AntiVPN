package me.braydon.antivpn.cache;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.model.AddressData;
import me.braydon.antivpn.service.AddressService;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.util.Set;

/**
 * A cache for {@link AddressData}.
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
     * The generation of the detection data and
     * policy lists this was computed with.
     */
    private final String generation;
    
    /**
     * Check if this cache includes all the given lookup data.
     * <p>
     * Redis doesn't store empty collections, so an entry
     * cached without lookup data comes back as null.
     * </p>
     *
     * @param requested the requested lookup data
     * @return true if every requested type is cached, otherwise false
     * @see #lookupData for lookup data
     */
    public boolean covers(@NonNull Set<AddressService.LookupData> requested) {
        return lookupData == null ? requested.isEmpty() : lookupData.containsAll(requested);
    }
    
    /**
     * Get the cached version of
     * the given address data.
     *
     * @param addressData the address data
     * @param lookupData  the lookup data used to fetch the address data
     * @param generation  the generation of the data used
     * @return the cached address data
     */
    @NonNull
    public static CachedAddressData asCache(@NonNull AddressData addressData, Set<AddressService.LookupData> lookupData,
                                            @NonNull String generation) {
        return new CachedAddressData(
            addressData.getIp(),
            lookupData,
            AntiVPN.GSON.toJson(addressData),
            System.currentTimeMillis(),
            generation
        );
    }
}
