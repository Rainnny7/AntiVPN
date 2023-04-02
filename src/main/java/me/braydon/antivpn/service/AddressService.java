package me.braydon.antivpn.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Continent;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.cache.CachedAddressData;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.repository.redis.AddressCacheRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "VPN Service")
public final class AddressService {
    /**
     * The regex expression for validating IPv4 addresses.
     */
    private static final String ADDRESS_REGEX = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$";
    
    /**
     * The regex expression for validating domains.
     */
    private static final String DOMAIN_REGEX = "^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]?\\.(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";
    
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
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    /**
     * Timestamps to keep track of so
     * we can properly tick the providers.
     */
    private long lastIpPurge;
    
    @Autowired
    public AddressService(@NonNull JedisConnectionFactory jedisFactory) {
        this.jedisFactory = jedisFactory;
    }
    
    /**
     * Initialize this component.
     */
    @PostConstruct
    public void initialize() {
        // Run the main tick task for addresses
        new Thread(() -> {
            long lastLog = 0L; // The last time we logged
            while (!Thread.currentThread().isInterrupted()) {
                boolean canLog = (System.currentTimeMillis() - lastLog) >= TimeUnit.SECONDS.toMillis(10L); // Check if we can log
                lastLog = System.currentTimeMillis(); // Update the last log to now
                
                Set<VPNServiceProvider> providers = VPNServiceProvider.getRegistry();
                if (canLog) { // Log that we're ticking providers
                    log.info("Ticking {} providers...", providers.size());
                }
                for (VPNServiceProvider provider : providers) {
                    // Scrape the provider
                    provider.scrape(jedisFactory);
                    
                    // Purge expired IPs
                    if ((System.currentTimeMillis() - lastIpPurge) >= TimeUnit.HOURS.toMillis(12L)) {
                        lastIpPurge = System.currentTimeMillis(); // Update the last ip purge to now
                        provider.purgeExpiredIps(jedisFactory); // Purge expired IPs
                    }
                }
                if (canLog) { // Log the GC
                    log.info("Running GC...");
                }
                System.gc(); // Run the garbage collector after ticking the providers
                
                // Default sleep delay
                try {
                    Thread.sleep(2500L);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }
        }, "Primary Address Thread").start();
    }
    
    /**
     * Data for an IP address.
     */
    @RequiredArgsConstructor(access = AccessLevel.PROTECTED)
    @Getter
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    @ToString
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AddressData {
        /**
         * The IP address.
         */
        @Id @EqualsAndHashCode.Include @NonNull private final String ip;
        
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
         * The ASN data of this address.
         * <p>
         * Only available if the lookup request specified it.
         * </p>
         *
         * @see AsnData for data
         */
        private final AsnData asn;
        
        /**
         * The geographical data of this address.
         * <p>
         * Only available if the lookup request specified it.
         * </p>
         *
         * @see GeographicalData for data
         */
        private final GeographicalData geographical;
        
        /**
         * The timestamp of when this address
         * was cached, null if not cached.
         */
        @Transient private Long cached;
        
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
         * Flag this address as cached.
         */
        public void flagCached(long timestamp) {
            cached = timestamp;
        }
        
        /**
         * Generate data for the given IP address.
         *
         * @param jedisFactory the jedis factory instance
         * @param rawIp        the ip
         * @param lookupData   the optional types of data to lookup
         * @param ignoreCache  whether we want to ignore the cache
         * @return the generated data
         * @see AddressLookupData the data type
         * @see JedisConnectionFactory for jedis factory
         */
        @NonNull @SneakyThrows
        public static AddressData from(@NonNull JedisConnectionFactory jedisFactory,
                                       @NonNull AddressCacheRepository addressCacheRepository,
                                       @NonNull String rawIp, Set<AddressService.AddressLookupData> lookupData,
                                       boolean ignoreCache) {
            boolean matchesDomain = rawIp.matches(DOMAIN_REGEX);
            if (!rawIp.matches(ADDRESS_REGEX) && !matchesDomain) { // Provided IP is not a valid IPv4 address or domain
                throw new IllegalArgumentException("Invalid IP address");
            }
            if (matchesDomain) { // Extract the IP from the domain
                rawIp = InetAddress.getByName(rawIp).getHostAddress();
            }
            String ip = rawIp; // The IP to lookup
            
            boolean lookupAsn = lookupData.contains(AddressLookupData.ASN); // Whether to lookup ASN data
            boolean lookupGeographical = lookupData.contains(AddressLookupData.GEOGRAPHICAL); // Whether to lookup geographical data
            log.info("Looking up data for IP: {}", ip); // Log the IP lookup
            
            // Checking the cache if we're not ignoring it
            if (!ignoreCache) {
                long beforeCache = System.currentTimeMillis(); // Before the cache lookup started
                Optional<CachedAddressData> optionalCache = addressCacheRepository.findById(ip);
                if (optionalCache.isPresent()) { // Return the cached data
                    CachedAddressData cache = optionalCache.get(); // The cached address data
                    AddressData addressData = AntiVPN.GSON.fromJson(cache.getJson(), AddressData.class);
                    boolean hasAllData = cache.hasLookupData() && cache.getLookupData().containsAll(lookupData); // Whether the cache has all the data we need
                    log.info("Found cached data for IP {} (Took {}ms){}",
                        ip,
                        System.currentTimeMillis() - beforeCache,
                        hasAllData ? "" : ", but it's missing data, running a full lookup..."
                    ); // Log that we found the cache
                    
                    if (hasAllData) { // Are we trying to lookup more data that we have cached?
                        addressData.flagCached(cache.getTimestamp()); // Flag the cached data
                        return addressData; // Return the cached data
                    }
                }
            }
            // Running a full lookup
            InetAddress inetAddress = InetAddress.getByName(ip); // The inet address
            float risk = 0.0f; // The calculated risk score
            List<Supplier<Float>> riskSuppliers = new ArrayList<>(); // The suppliers for calculating the risk score
            
            AtomicBoolean vpnProvider = new AtomicBoolean(); // Whether this address belongs to a VPN provider
            Set<BlacklistType> blacklisted = new HashSet<>(); // The types of blacklists this address is on
            
            // Extra data to fetch
            AtomicReference<AsnData> asnData = new AtomicReference<>(null);
            AtomicReference<GeographicalData> geographicalData = new AtomicReference<>(null);
            
            // Check if the IP belongs to any provider
            riskSuppliers.add(() -> {
                long before = System.currentTimeMillis(); // The time before the lookup
                float providerRisk = 0.0f; // The risk score for the provider
                for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
                    if (!provider.hasIp(jedisFactory, ip)) { // Provider doesn't have this IP
                        continue;
                    }
                    vpnProvider.set(true); // IP belongs to a provider
                    providerRisk += 0.6;
                }
                log.info("VPN provider lookup complete in {}ms", System.currentTimeMillis() - before); // Log timings
                return providerRisk;
            });
            
            // Looking up the ASN of the IP if specified in the lookup data
            if (lookupAsn) {
                log.info("Looking up ASN of IP: {}", ip); // Log the ASN lookup
                riskSuppliers.add(() -> {
                    long before = System.currentTimeMillis(); // The time before the lookup
                    AtomicReference<Float> asnRisk = new AtomicReference<>();
                    MaxmindService.getInstance().submitTask(databaseReader -> {
                        try {
                            AsnResponse asnResponse = databaseReader.asn(inetAddress);
                            
                            // Set the response
                            asnData.set(new AsnData(
                                asnResponse.getAutonomousSystemNumber(),
                                asnResponse.getAutonomousSystemOrganization(),
                                asnResponse.getNetwork().toString()
                            ));
                            
                            // Checking if the ASN number is blacklisted
                            if (BLACKLISTED_ASN_NUMBERS.contains(asnData.get().getNumber())) {
                                blacklisted.add(BlacklistType.ASN);
                                asnRisk.set(0.4f);
                            }
                            log.info("ASN data lookup complete in {}ms", System.currentTimeMillis() - before); // Log timings
                        } catch (IOException | GeoIp2Exception ex) {
                            ex.printStackTrace();
                        }
                    });
                    return asnRisk.get();
                });
            }
            
            // Looking up the geographical data of the IP if specified in the lookup data
            if (lookupGeographical) {
                log.info("Looking up geographical data of IP: {}", ip); // Log the geo lookup
                riskSuppliers.add(() -> {
                    long before = System.currentTimeMillis(); // The time before the lookup
                    AtomicReference<Float> countryRisk = new AtomicReference<>();
                    MaxmindService.getInstance().submitTask(databaseReader -> {
                        try {
                            CityResponse cityResponse = databaseReader.city(inetAddress);
                            Location location = cityResponse.getLocation(); // The location of the IP
                            Continent continent = cityResponse.getContinent(); // The continent of the IP
                            Country country = cityResponse.getCountry(); // The country of the IP
                            City city = cityResponse.getCity(); // The city of the IP
                            
                            // Set the response
                            geographicalData.set(new GeographicalData(
                                continent.getCode(),
                                continent.getName(),
                                country.getIsoCode(),
                                country.getName(),
                                country.isInEuropeanUnion(),
                                city == null ? null : city.getName(), // How can this be null..?
                                location.getLatitude(),
                                location.getLongitude(),
                                location.getTimeZone()
                            ));
                            
                            System.out.println("location.getAccuracyRadius() = " + location.getAccuracyRadius());
                            
                            // Checking if the country is blacklisted
                            if (BLACKLISTED_COUNTRIES.contains(country.getName())) {
                                blacklisted.add(BlacklistType.COUNTRY);
                                countryRisk.set(0.4f);
                            }
                            log.info("Geographical data lookup complete in {}ms", System.currentTimeMillis() - before); // Log timings
                        } catch (IOException | GeoIp2Exception ex) {
                            ex.printStackTrace();
                        }
                    });
                    return countryRisk.get();
                });
            }
            
            // Calculating the risk
            long before = System.currentTimeMillis();
            for (Supplier<Float> supplier : riskSuppliers) {
                Float value = supplier.get();
                if (value == null || (value.isNaN() || value.isInfinite())) {
                    continue;
                }
                risk += value;
            }
            risk = Math.min(risk, 1.0f); // Limit the risk to 1.0
            log.info("Risk calculation complete in {}ms", System.currentTimeMillis() - before); // Log timings
            
            // Return the address data
            AddressData addressData = new AddressData(
                ip, // The IP address
                risk, // The risk score we calculated
                vpnProvider.get(), // Is the IP from a VPN provider?
                blacklisted, // The blacklists the IP may be apart of
                asnData.get(), // The ASN data of the IP
                geographicalData.get() // The geographical data of the IP
            );
            // Cache the address data
            addressCacheRepository.save(new CachedAddressData(
                ip,
                lookupData,
                AntiVPN.GSON.toJson(addressData),
                System.currentTimeMillis()
            ));
            return addressData;
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
            @NonNull private final String organization;
            
            /**
             * The network this ASN belongs to.
             */
            @NonNull private final String network;
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
            @NonNull private final String continentCode;
            
            /**
             * The originating continent of an IP address.
             */
            @NonNull private final String continent;
            
            /**
             * The originating country ISO code of an IP address.
             */
            @NonNull private final String countryIsoCode;
            
            /**
             * The originating country of an IP address.
             */
            @NonNull private final String country;
            
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
            @NonNull private final double latitude;
            
            /**
             * The longitude of the location of an IP address.
             */
            @NonNull private final double longitude;
            
            /**
             * The timezone of the location of an IP address.
             */
            @NonNull private final String timezone;
        }
    }
    
    /**
     * The additional data you can optionally lookup.
     */
    public enum AddressLookupData {
        ASN,
        GEOGRAPHICAL
    }
    
    /**
     * The type of blacklists.
     */
    public enum BlacklistType {
        ASN,
        COUNTRY
    }
}
