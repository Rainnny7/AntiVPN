package me.braydon.antivpn.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import me.braydon.antivpn.detection.Detection;

import java.util.List;
import java.util.Set;

/**
 * Data for an IP address.
 *
 * @author Braydon
 */
@RequiredArgsConstructor
@Getter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AddressData {
    /**
     * The IP address.
     */
    @EqualsAndHashCode.Include @NonNull private final String ip;
    
    /**
     * The type of this IP address.
     */
    private final int ipType;
    
    /**
     * The risk score of this IP address, between 0 and 1.
     */
    private final float risk;
    
    /**
     * Whether this address is a VPN server.
     */
    private final boolean vpn;
    
    /**
     * Whether this address was found in a VPN provider's own server list.
     */
    private final boolean vpnProvider;
    
    /**
     * The name of the VPN provider, null if unknown.
     */
    private final String provider;
    
    /**
     * Whether this address is a Tor exit node.
     */
    private final boolean tor;
    
    /**
     * Whether this address is a consumer privacy relay (iCloud Private Relay).
     */
    private final boolean relay;
    
    /**
     * Whether this address belongs to a datacenter or hosting network.
     */
    private final boolean hosting;
    
    /**
     * Whether this address is on an abuse list.
     */
    private final boolean abuse;
    
    /**
     * Whether this address is allowlisted.
     */
    private final boolean allowlisted;
    
    /**
     * The blacklists this address is on.
     */
    @NonNull private final Set<Blacklist.BlacklistType> blacklists;
    
    /**
     * The signals that matched this address.
     */
    @NonNull private final List<Detection> detections;
    
    /**
     * The ASN data of this address.
     * <p>
     * Only available if the lookup request specified it.
     * </p>
     *
     * @see AddressData.AsnData for data
     */
    private final AsnData asn;
    
    /**
     * The geographical data of this address.
     * <p>
     * Only available if the lookup request specified it.
     * </p>
     *
     * @see AddressData.GeographicalData for data
     */
    private final GeographicalData geographical;
    
    /**
     * The timestamp of when this address
     * was cached, null if not cached.
     */
    private transient Long cached;
    
    /**
     * Check if this address is
     * on the given blacklist.
     *
     * @param type the blacklist type
     * @return true if blacklisted, otherwise false
     * @see Blacklist.BlacklistType for type
     */
    public boolean isOnBlacklist(@NonNull Blacklist.BlacklistType type) {
        return blacklists.contains(type);
    }
    
    /**
     * Flag this address as cached.
     */
    public void flagCached(long timestamp) {
        cached = timestamp;
    }
    
    /**
     * The ASN data of an IP address.
     */
    @AllArgsConstructor
    @Getter
    @ToString
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AsnData {
        /**
         * The ASN number of an IP address.
         */
        private final long number;
        
        /**
         * The organization this ASN belongs to.
         */
        private final String organization;
        
        /**
         * The network this ASN belongs to.
         */
        private final String network;
    }
    
    /**
     * The geographical data of an IP address.
     */
    @AllArgsConstructor
    @Getter
    @ToString
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class GeographicalData {
        /**
         * The originating continent code of an IP address.
         */
        private final String continentCode;
        
        /**
         * The originating continent of an IP address.
         */
        private final String continent;
        
        /**
         * The originating country ISO code of an IP address.
         */
        private final String countryIsoCode;
        
        /**
         * The originating country of an IP address.
         */
        private final String country;
        
        /**
         * Whether the originating country is part of the European Union.
         */
        private final boolean europeanUnion;
        
        /**
         * The originating city of an IP address.
         */
        private final String city;
        
        /**
         * The latitude of the location of an IP address.
         */
        private final Double latitude;
        
        /**
         * The longitude of the location of an IP address.
         */
        private final Double longitude;
        
        /**
         * The timezone of the location of an IP address.
         */
        private final String timezone;
    }
}
