package me.braydon.antivpn.service;

import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Continent;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import inet.ipaddr.IPAddress;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.cache.CachedAddressData;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.detection.Detection;
import me.braydon.antivpn.detection.DetectionEngine;
import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.metric.impl.RequestTracker;
import me.braydon.antivpn.model.AddressData;
import me.braydon.antivpn.model.Blacklist;
import me.braydon.antivpn.repository.AddressCacheRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "VPN Service")
public class AddressService {
    /**
     * The pattern for validating domains.
     */
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
    );
    
    @NonNull private final MetricService metrics;
    @NonNull private final AddressCacheRepository addressCacheRepository;
    @NonNull private final DetectionService detectionService;
    @NonNull private final DetectionEngine detectionEngine;
    @NonNull private final PolicyListService policyListService;
    @NonNull private final MaxmindService maxmindService;
    
    public AddressService(@NonNull MetricService metrics, @NonNull AddressCacheRepository addressCacheRepository,
                          @NonNull DetectionService detectionService, @NonNull DetectionEngine detectionEngine,
                          @NonNull PolicyListService policyListService, @NonNull MaxmindService maxmindService) {
        this.metrics = metrics;
        this.addressCacheRepository = addressCacheRepository;
        this.detectionService = detectionService;
        this.detectionEngine = detectionEngine;
        this.policyListService = policyListService;
        this.maxmindService = maxmindService;
    }
    
    /**
     * Lookup data for the given IP address or domain.
     *
     * @param input       the ip or domain to lookup
     * @param data        the extra data to include in the response
     * @param ignoreCache should we bypass the cache?
     * @return the address data
     * @throws APIException when the input is invalid or private
     * @see AddressData for address data
     * @see LookupData for lookup data
     */
    @NonNull
    public AddressData lookup(@NonNull String input, @NonNull Set<LookupData> data, boolean ignoreCache) {
        long started = System.currentTimeMillis(); // Just started
        try {
            IPAddress address = resolve(input);
            if (IPUtils.isReserved(address)) {
                throw new APIException(HttpStatus.BAD_REQUEST, "Cannot lookup private or reserved IP ranges");
            }
            String ip = address.toCanonicalString();
            String generation = detectionService.getGeneration() + ":" + policyListService.getVersion();
            
            // Handle the cache
            if (!ignoreCache) {
                Optional<AddressData> cached = findCached(ip, data, generation);
                if (cached.isPresent()) {
                    return cached.get();
                }
            }
            metrics.getTracker(DatabaseTracker.class).submitCacheMiss(); // Cache missed
            
            InetAddress inetAddress = address.toInetAddress();
            AddressData.AsnData asnData = maxmindService.asn(inetAddress).map(AddressService::toAsnData).orElse(null);
            AddressData.GeographicalData geographicalData = maxmindService.city(inetAddress).map(AddressService::toGeographicalData).orElse(null);
            Long asn = asnData == null || asnData.getNumber() == 0L ? null : asnData.getNumber();
            
            List<Detection> detections = detectionService.lookup(address, asn);
            boolean allowlisted = policyListService.isAllowlisted(address, asn);
            Set<Blacklist.BlacklistType> blacklists = policyListService.getBlacklists(asn,
                geographicalData == null ? null : geographicalData.getCountryIsoCode(),
                geographicalData == null ? null : geographicalData.getCountry()
            );
            DetectionEngine.Verdict verdict = detectionEngine.evaluate(detections, allowlisted, blacklists);
            
            // Building the address data
            AddressData addressData = new AddressData(
                ip,
                IPUtils.getIpType(address),
                verdict.risk(),
                verdict.vpn(),
                verdict.vpnProvider(),
                verdict.provider(),
                verdict.tor(),
                verdict.relay(),
                verdict.hosting(),
                verdict.abuse(),
                verdict.allowlisted(),
                verdict.blacklists(),
                verdict.detections(),
                data.contains(LookupData.ASN) ? asnData : null,
                data.contains(LookupData.GEOGRAPHICAL) ? geographicalData : null
            );
            saveCached(addressData, data, generation);
            return addressData;
        } finally {
            metrics.getTracker(RequestTracker.class).submitLookup(); // Metrics
            log.debug("Finished lookup for '{}', took {}ms", input, System.currentTimeMillis() - started); // Logging
        }
    }
    
    /**
     * Parse the given input as an IP address, resolving it first if it's a domain.
     *
     * @param input the input
     * @return the address
     * @throws APIException if the input is invalid or can't be resolved
     */
    @NonNull
    private static IPAddress resolve(@NonNull String input) {
        Optional<IPAddress> address = IPUtils.parseAddress(input);
        if (address.isPresent()) {
            return address.get();
        }
        String domain = input.trim().toLowerCase(Locale.ROOT);
        if (!DOMAIN_PATTERN.matcher(domain).matches()) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Invalid IP address or domain: " + input);
        }
        try {
            String resolved = InetAddress.getByName(domain).getHostAddress();
            return IPUtils.parseAddress(resolved).orElseThrow(() -> new UnknownHostException(domain));
        } catch (UnknownHostException ex) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Could not resolve domain: " + domain);
        }
    }
    
    @NonNull
    private Optional<AddressData> findCached(@NonNull String ip, @NonNull Set<LookupData> data, @NonNull String generation) {
        long before = System.currentTimeMillis(); // Current timestamp for metrics
        try {
            Optional<CachedAddressData> optionalCache = addressCacheRepository.findById(ip);
            if (optionalCache.isEmpty()) {
                return Optional.empty();
            }
            CachedAddressData cache = optionalCache.get(); // The cached address data
            if (!generation.equals(cache.getGeneration())) { // Computed with older detection data
                return Optional.empty();
            }
            if (!cache.covers(data)) { // Missing data we need
                return Optional.empty();
            }
            AddressData addressData = AntiVPN.GSON.fromJson(cache.getJson(), AddressData.class);
            metrics.getTracker(DatabaseTracker.class).submitCacheHit(); // Cache hit
            addressData.flagCached(cache.getTimestamp()); // Flag the cached data
            return Optional.of(addressData);
        } catch (Exception ex) {
            log.warn("Address cache lookup failed for {}: {}", ip, ex.toString());
            return Optional.empty();
        } finally {
            metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                DatabaseTracker.DatabaseType.REDIS, System.currentTimeMillis() - before); // Time Redis
        }
    }
    
    private void saveCached(@NonNull AddressData addressData, @NonNull Set<LookupData> data, @NonNull String generation) {
        try {
            addressCacheRepository.save(CachedAddressData.asCache(addressData, Set.copyOf(data), generation));
        } catch (Exception ex) {
            log.warn("Failed to cache lookup for {}: {}", addressData.getIp(), ex.toString());
        }
    }
    
    @NonNull
    private static AddressData.AsnData toAsnData(@NonNull AsnResponse response) {
        return new AddressData.AsnData(
            response.autonomousSystemNumber() == null ? 0L : response.autonomousSystemNumber(),
            response.autonomousSystemOrganization(),
            response.network() == null ? null : response.network().toString()
        );
    }
    
    @NonNull
    private static AddressData.GeographicalData toGeographicalData(@NonNull CityResponse response) {
        Location location = response.location(); // The location from the response
        Continent continent = response.continent(); // The continent from the response
        Country country = response.country(); // The country from the response
        City city = response.city(); // The city from the response
        return new AddressData.GeographicalData(
            continent == null ? null : continent.code(),
            continent == null ? null : continent.name(),
            country == null ? null : country.isoCode(),
            country == null ? null : country.name(),
            country != null && country.isInEuropeanUnion(),
            city == null ? null : city.name(),
            location == null ? null : location.latitude(),
            location == null ? null : location.longitude(),
            location == null ? null : location.timeZone()
        );
    }
    
    /**
     * Different types of data to
     * lookup for an IP address.
     */
    public enum LookupData {
        ASN,
        GEOGRAPHICAL
    }
}
