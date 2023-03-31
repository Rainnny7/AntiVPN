package me.braydon.antivpn.service;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CountryResponse;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.repository.redis.AddressCacheRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "VPN Service")
@Order(20)
public final class AddressService {
    /**
     * The regex expression for validating IPv4 addresses.
     */
    private static final String ADDRESS_REGEX = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$";
    
    /**
     * The blacklisted ASN numbers.
     * TODO: Make this automatic somehow, or at least configurable
     */
    public static final Set<Long> BLACKLISTED_ASN_NUMBERS = new HashSet<>();
    
    /**
     * The blacklisted countries.
     * TODO: Make this automatic somehow, or at least configurable
     */
    public static final Set<String> BLACKLISTED_COUNTRIES = new HashSet<>();
    
    static {
        // ASN Numbers
        BLACKLISTED_ASN_NUMBERS.add(212238L);
        BLACKLISTED_ASN_NUMBERS.add(18345L);
        
        // Countries
        BLACKLISTED_COUNTRIES.add("Australia");
    }
    
    /**
     * The {@link AddressCacheRepository} to use.
     */
    @NonNull private final AddressCacheRepository addressCacheRepository;
    
    @Autowired
    public AddressService(@NonNull AddressCacheRepository addressCacheRepository) {
        this.addressCacheRepository = addressCacheRepository;
    }
    
    /**
     * Initialize this component.
     */
    @PostConstruct
    public void initialize() {
        // Schedule a task to scrape providers
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
                    provider.scrape();
                }
            }
        }, 2500L, 2500L);
        
        // Schedule a task to purge all expired IPs
        long purgeDelay = TimeUnit.HOURS.toMillis(12L);
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
                    provider.purgeExpiredIps();
                }
            }
        }, purgeDelay, purgeDelay);
        
        // Schedule a task to save the config files of all providers
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
                    provider.save();
                }
            }
        }, TimeUnit.MINUTES.toMillis(1L), TimeUnit.MINUTES.toMillis(5L));
    }
    
    /**
     * Data for an IP address.
     */
    @AllArgsConstructor(access = AccessLevel.PROTECTED)
    @Getter
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    @ToString
    public static class AddressData {
        /**
         * The IP address.
         */
        @EqualsAndHashCode.Include @NonNull private final String ip;
        
        /**
         * The risk score of this IP address.
         */
        private final float risk;
        
        /**
         * Whether this address belongs to a VPN provider.
         *
         * @see VPNServiceProvider for provider
         */
        private final boolean vpnProvider;
        
        /**
         * The blacklists this address is on.
         */
        @NonNull private final Set<BlacklistType> blacklists;
        
        /**
         * The ASN number of this address.
         * <p>
         * Only available if the lookup request specified it.
         * </p>
         */
        private final Long asn;
        
        /**
         * The geographical data of this address.
         *
         * @see GeographicalData for data
         */
        @NonNull private final GeographicalData geographical;
        
        /**
         * Check if this address is
         * on the given blacklist.
         *
         * @param type the blacklist type
         * @return true if blacklisted, otherwise false
         * @see BlacklistType for type
         */
        public boolean isOnBlacklist(@NonNull BlacklistType type) {
            return blacklists.contains(type);
        }
        
        /**
         * Generate data for the given IP address.
         *
         * @param ip         the ip
         * @param lookupData the optional types of data to lookup
         * @return the generated data
         * @see AddressLookupData the data type
         */
        @NonNull @SneakyThrows
        public static AddressData from(@NonNull String ip, Set<AddressService.AddressLookupData> lookupData) {
            if (!ip.matches(ADDRESS_REGEX)) { // Provided IP is not a valid IPv4 address
                throw new IllegalArgumentException("Invalid IP address");
            }
            log.info("Looking up data for IP: {}", ip); // Log the IP lookup
            InetAddress inetAddress = InetAddress.getByName(ip); // The inet address
            float risk = 0.0f; // The calculated risk score
            
            AtomicBoolean vpnProvider = new AtomicBoolean(); // Whether this address belongs to a VPN provider
            Set<BlacklistType> blacklisted = new HashSet<>(); // The types of blacklists this address is on
            AtomicLong asn = new AtomicLong(); // The ASN number of this address
            
            // Geographical data
            AtomicReference<String> continent = new AtomicReference<>();
            AtomicReference<String> country = new AtomicReference<>();
            
            // The suppliers for calculating the risk score
            List<Supplier<Float>> riskSuppliers = new ArrayList<>();
            
            // Check if the IP belongs to any provider
            riskSuppliers.add(() -> {
                for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
                    if (!provider.hasIp(ip)) { // Provider doesn't have this IP
                        continue;
                    }
                    vpnProvider.set(true); // IP belongs to a provider
                    return 0.6f;
                }
                return 0f;
            });
            
            // Looking up the ASN of the IP if specified in the lookup data
            if (lookupData.contains(AddressLookupData.ASN)) {
                log.info("Looking up ASN of IP: {}", ip); // Log the ASN lookup
                riskSuppliers.add(() -> {
                    AtomicReference<Float> asnRisk = new AtomicReference<>();
                    MaxmindService.getInstance().submitTask(databaseReader -> {
                        try {
                            AsnResponse asnResponse = databaseReader.asn(inetAddress);
                            asn.set(asnResponse.getAutonomousSystemNumber()); // The ASN number
                            
                            // Checking the blacklist
                            if (BLACKLISTED_ASN_NUMBERS.contains(asn.get())) {
                                blacklisted.add(BlacklistType.ASN);
                                asnRisk.set(0.4f);
                            }
                        } catch (IOException | GeoIp2Exception ex) {
                            ex.printStackTrace();
                        }
                    });
                    return asnRisk.get();
                });
            }
            
            // Looking up the country of the IP if specified in the lookup data
            if (lookupData.contains(AddressLookupData.COUNTRY)) {
                log.info("Looking up country of IP: {}", ip); // Log the country lookup
                riskSuppliers.add(() -> {
                    AtomicReference<Float> countryRisk = new AtomicReference<>();
                    MaxmindService.getInstance().submitTask(databaseReader -> {
                        try {
                            CountryResponse countryResponse = databaseReader.country(inetAddress);
                            continent.set(countryResponse.getContinent().getName()); // The continent
                            country.set(countryResponse.getCountry().getName()); // The country
                            
                            // Checking the blacklist
                            if (BLACKLISTED_COUNTRIES.contains(country.get())) {
                                blacklisted.add(BlacklistType.COUNTRY);
                                countryRisk.set(0.4f);
                            }
                        } catch (IOException | GeoIp2Exception ex) {
                            ex.printStackTrace();
                        }
                    });
                    return countryRisk.get();
                });
            }
            
            // Calculating the risk
            for (Supplier<Float> supplier : riskSuppliers) {
                Float value = supplier.get();
                if (value == null || (value.isNaN() || value.isInfinite())) {
                    continue;
                }
                risk += value;
            }
            risk = Math.min(risk, 1.0f); // Ensure the risk doesn't exceed 1.0
            
            // Return the address data
            return new AddressData(
                ip,
                risk,
                vpnProvider.get(),
                blacklisted,
                asn.get(),
                new GeographicalData(
                    continent.get(),
                    country.get()
                )
            );
        }
    
        /**
         * The geographical data of an IP address.
         */
        @AllArgsConstructor @Getter @ToString
        public static class GeographicalData {
            /**
             * The originating continent of an IP address.
             * <p>
             * Only available if the lookup request specified it.
             * </p>
             */
            private final String continent;
            
            /**
             * The originating country of an IP address.
             * <p>
             * Only available if the lookup request specified it.
             * </p>
             */
            private final String country;
        }
    }
    
    /**
     * The additional data you can optionally lookup.
     */
    public enum AddressLookupData {
        ASN,
        COUNTRY
    }
    
    /**
     * The type of blacklists.
     */
    public enum BlacklistType {
        ASN,
        COUNTRY
    }
}
