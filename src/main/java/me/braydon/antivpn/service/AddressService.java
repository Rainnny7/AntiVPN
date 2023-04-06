package me.braydon.antivpn.service;

import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Continent;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.cache.CachedAddressData;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.metric.impl.RequestTracker;
import me.braydon.antivpn.model.AddressData;
import me.braydon.antivpn.model.Blacklist;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.repository.AddressCacheRepository;
import me.braydon.antivpn.repository.blacklist.BlacklistRepository;
import org.apache.commons.net.util.SubnetUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "VPN Service")
public final class AddressService {
    /**
     * The regex expression for validating domains.
     */
    private static final String DOMAIN_REGEX = "^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]?\\.(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";
    
    /**
     * Private subnets to disallow lookups for.
     */
    private static final String[] PRIVATE_SUBNETS = {
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.0.0/29",
        "192.0.0.8/32",
        "192.0.0.9/32",
        "192.0.0.10/32",
        "192.0.0.170/32",
        "192.0.0.171/32",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32"
    };
    
    /**
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    /**
     * The metrics service instance to use.
     *
     * @see MetricService for metrics service
     */
    @NonNull private final MetricService metrics;
    
    /**
     * The address cache repository.
     *
     * @see AddressCacheRepository for address cache repository
     */
    @NonNull private final AddressCacheRepository addressCacheRepository;
    
    /**
     * The blacklist repository.
     *
     * @see BlacklistRepository for blacklist repository
     */
    @NonNull private final BlacklistRepository blacklistRepository;
    
    /**
     * Timestamps to keep track of so
     * we can properly tick the providers.
     */
    private long lastIpPurge;
    
    @Autowired
    public AddressService(@NonNull JedisConnectionFactory jedisFactory, @NonNull MetricService metrics,
                          @NonNull AddressCacheRepository addressCacheRepository, @NonNull BlacklistRepository blacklistRepository) {
        this.jedisFactory = jedisFactory;
        this.metrics = metrics;
        this.addressCacheRepository = addressCacheRepository;
        this.blacklistRepository = blacklistRepository;
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
                AtomicInteger completed = new AtomicInteger(0); // The amount of providers that have completed
                providers.parallelStream().forEach(provider -> {
                    // Scrape the provider
                    provider.scrape(jedisFactory);
                    completed.incrementAndGet(); // Increment the completed providers
                    
                    // Purge expired IPs
                    if ((System.currentTimeMillis() - lastIpPurge) >= TimeUnit.HOURS.toMillis(12L)) {
                        lastIpPurge = System.currentTimeMillis(); // Update the last ip purge to now
                        provider.purgeExpiredIps(jedisFactory); // Purge expired IPs
                    }
                });
                // Wait for all providers to complete
                while (completed.get() != providers.size()) {
                    try {
                        Thread.sleep(100L);
                    } catch (InterruptedException ex) {
                        ex.printStackTrace();
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
     * Lookup data for the given IP address.
     *
     * @param ip          the ip to lookup
     * @param data        the data to lookup
     * @param ignoreCache should we bypass the cache?
     * @return the address data
     * @throws APIException when an exception occurs
     * @see AddressData for address data
     * @see LookupData for lookup data
     */
    @NonNull @SneakyThrows
    public AddressData lookup(@NonNull String ip, Set<LookupData> data, boolean ignoreCache) {
        log.info("Looking up data for IP '{}'...", ip); // Logging
        long started = System.currentTimeMillis(); // Just started
        try {
            if (IPUtils.getIpType(ip) == -1) { // IP is not v4 or v6
                throw new APIException(HttpStatus.BAD_REQUEST, "Invalid IP address: " + ip);
            }
            // Prevent lookups of private IP ranges
            for (String subnet : PRIVATE_SUBNETS) {
                SubnetUtils.SubnetInfo subnetInfo = new SubnetUtils(subnet).getInfo();
                if (subnetInfo.isInRange(ip)) {
                    throw new APIException(HttpStatus.BAD_REQUEST, "Cannot lookup private IP ranges");
                }
            }
            log.info("IP Range lookup took {}ms", System.currentTimeMillis() - started); // Debug
            
            InetAddress inetAddress = null;
            
            // Extract the IP from the domain
            if (ip.matches(DOMAIN_REGEX)) {
                String domain = ip;
                inetAddress = InetAddress.getByName(domain); // Get the inet address
                ip = inetAddress.getHostAddress(); // Get the IP address
                log.info("Extracted IP ({}) from domain ({}), took {}ms", ip, domain, System.currentTimeMillis() - started); // Logging
            }
            // Handle the cache
            if (!ignoreCache) {
                long before = System.currentTimeMillis(); // Current timestamp for metrics
                try { // Attempt to lookup from the cache
                    Optional<CachedAddressData> optionalCache = addressCacheRepository.findById(ip);
                    if (optionalCache.isPresent()) { // Return the cached data
                        CachedAddressData cache = optionalCache.get(); // The cached address data
                        AddressData addressData = AntiVPN.GSON.fromJson(cache.getJson(), AddressData.class);
                        boolean hasAllData = cache.hasLookupData() && cache.getLookupData().containsAll(data); // Whether the cache has all the data we need
                        
                        // Log that we found the cache
                        log.info("Found cached data for IP {} (Took {}ms){}",
                            ip,
                            System.currentTimeMillis() - before,
                            hasAllData ? "" : ", but it's missing data, running a full lookup..."
                        );
                        
                        // Returning the cached data if we have all the data we need
                        if (hasAllData) {
                            metrics.getTracker(DatabaseTracker.class).submitCacheHit(); // Cache hit
                            addressData.flagCached(cache.getTimestamp()); // Flag the cached data
                            return addressData; // Return the cached data
                        }
                    }
                } finally {
                    metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                        DatabaseTracker.DatabaseType.REDIS, System.currentTimeMillis() - before); // Time Redis
                    log.info("Cache lookup took {}ms", System.currentTimeMillis() - before); // Debug
                }
            }
            if (inetAddress == null) { // Get the inet address if we don't have it already
                inetAddress = InetAddress.getByName(ip);
            }
            // Cannot lookup loopback or local addresses
            if (inetAddress.isLoopbackAddress() || inetAddress.isSiteLocalAddress()) {
                throw new IllegalArgumentException("Cannot lookup loopback or local addresses");
            }
            metrics.getTracker(DatabaseTracker.class).submitCacheMiss(); // Cache missed
            
            boolean lookupAsn = data.contains(LookupData.ASN); // Lookup ASN data?
            boolean lookupGeographical = data.contains(LookupData.GEOGRAPHICAL); // Lookup geo data?
            log.info("Looking up data for IP (asn={}, geo={}): {}", lookupAsn, lookupGeographical, ip); // Logging
            
            // Data to return
            boolean vpnProvider = false; // Does the IP belong to a VPN provider?
            Set<Blacklist.BlacklistType> blacklists = new HashSet<>(); // Blacklists the IP is apart of
            AddressData.AsnData asnData = null; // ASN data
            AddressData.GeographicalData geographicalData = null; // Geographical data
            
            // Calculating the risk score based on weights
            float risk = 0f;
            
            // Use the highest weight for IPs belonging to VPN providers
            for (VPNServiceProvider serviceProvider : VPNServiceProvider.getRegistry()) {
                if (serviceProvider.hasIp(jedisFactory, ip, true)) {
                    log.info("IP belongs to VPN provider: {}", serviceProvider.getName()); // Logging
                    vpnProvider = true;
                    risk += 1f;
                    break;
                }
            }
            log.info("VPN provider lookup took {}ms", System.currentTimeMillis() - started); // Debug
            
            // Calculating the ASN weight
            if (lookupAsn) {
                log.info("Looking up ASN data..."); // Logging
                asnData = (AddressData.AsnData) LookupData.ASN.execute(inetAddress);
                
                // Checking the ASN blacklist
                if (blacklistRepository.contains(Blacklist.BlacklistType.ASN, String.valueOf(asnData.getNumber()))) {
                    log.info("ASN is blacklisted: {}", asnData.getNumber()); // Logging
                    blacklists.add(Blacklist.BlacklistType.ASN);
                    risk += 0.5f;
                }
                log.info("ASN lookup took {}ms", System.currentTimeMillis() - started); // Debug
            }
            // Calculating the GEO weight
            if (lookupGeographical) {
                log.info("Looking up GEO data..."); // Logging
                geographicalData = (AddressData.GeographicalData) LookupData.GEOGRAPHICAL.execute(inetAddress);
                
                // Checking the ASN blacklist
                if (blacklistRepository.contains(Blacklist.BlacklistType.COUNTRY, geographicalData.getCountry())) {
                    log.info("Country is blacklisted: {}", geographicalData.getCountry()); // Logging
                    blacklists.add(Blacklist.BlacklistType.COUNTRY);
                    risk += 0.4f;
                }
                log.info("Geographical lookup took {}ms", System.currentTimeMillis() - started); // Debug
            }
            risk = Math.min(risk, 1.0f); // Limit the risk to 1.0
            
            // Building the address data
            AddressData addressData = new AddressData(
                ip, // The IP address
                IPUtils.getIpType(ip), // Get the IP type
                risk, // The risk score we calculated
                vpnProvider, // Is the IP from a VPN provider?
                blacklists, // The blacklists the IP may be apart of
                asnData, // The ASN data of the IP
                geographicalData // The geographical data of the IP
            );
            addressCacheRepository.save(CachedAddressData.asCache(addressData, data)); // Cache the response
            return addressData;
        } finally {
            metrics.getTracker(RequestTracker.class).submitLookup(); // Metrics
            log.info("Finished lookup for IP '{}', took {}ms", ip, System.currentTimeMillis() - started); // Logging
        }
    }
    
    /**
     * Different types of data to
     * lookup for an IP address.
     */
    @AllArgsConstructor @Getter
    public enum LookupData {
        ASN(MaxmindService.MaxmindDatabase.ASN) {
            @Override @NonNull @SneakyThrows
            public AddressData.AsnData execute(@NonNull InetAddress inetAddress) {
                AsnResponse response = getMaxmindDatabase().getDatabaseReader().asn(inetAddress);
                return new AddressData.AsnData(
                    response.getAutonomousSystemNumber(),
                    response.getAutonomousSystemOrganization(),
                    response.getNetwork().toString()
                );
            }
        },
        GEOGRAPHICAL(MaxmindService.MaxmindDatabase.CITY) {
            @Override @NonNull @SneakyThrows
            public AddressData.GeographicalData execute(@NonNull InetAddress inetAddress) {
                CityResponse cityResponse = getMaxmindDatabase().getDatabaseReader().city(inetAddress);
                Location location = cityResponse.getLocation(); // The location from the response
                Continent continent = cityResponse.getContinent(); // The continent from the response
                Country country = cityResponse.getCountry(); // The country from the response
                City city = cityResponse.getCity(); // The city from the response
                
                return new AddressData.GeographicalData(
                    continent.getCode(),
                    continent.getName(),
                    country.getIsoCode(),
                    country.getName(),
                    country.isInEuropeanUnion(),
                    city == null ? null : city.getName(), // How can this be null..?
                    location.getLatitude(),
                    location.getLongitude(),
                    location.getTimeZone()
                );
            }
        };
        
        /**
         * The {@link MaxmindService.MaxmindDatabase} to use for this lookup data.
         */
        @NonNull private final MaxmindService.MaxmindDatabase maxmindDatabase;
        
        @NonNull
        public Object execute(@NonNull InetAddress inetAddress) {
            throw new UnsupportedOperationException("Not implemented");
        }
    }
}
