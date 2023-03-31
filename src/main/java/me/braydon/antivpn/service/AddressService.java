package me.braydon.antivpn.service;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
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
import java.util.concurrent.atomic.AtomicBoolean;
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
    
    static {
        BLACKLISTED_ASN_NUMBERS.add(212238L);
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
         * Whether this address has a blacklisted ASN.
         */
        private final boolean blacklistedAsn;
        
        /**
         * Whether this address has a blacklisted hostname.
         */
        private final boolean blacklistedHostname;
        
        /**
         * Whether this address is in a blacklisted country.
         */
        private final boolean blacklistedCountry;
        
        /**
         * Generate data for the given IP address.
         *
         * @param ip the ip
         * @return the generated data
         */
        @NonNull @SneakyThrows
        public static AddressData from(@NonNull String ip) {
            if (!ip.matches(ADDRESS_REGEX)) { // Provided IP is not a valid IPv4 address
                throw new IllegalArgumentException("Invalid IP address");
            }
            InetAddress inetAddress = InetAddress.getByName(ip);
            
            float risk = 0.0f; // The risk score
            AtomicBoolean vpnProvider = new AtomicBoolean(); // Whether this address belongs to a VPN provider
            AtomicBoolean blacklistedAsn = new AtomicBoolean(); // Whether this address has a blacklisted ASN
            List<Supplier<Float>> riskSuppliers = new ArrayList<>(); // The suppliers for the risk score
            
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
            
            // Check if the IP has a blacklisted ASN
            riskSuppliers.add(() -> {
                AtomicReference<Float> asnRisk = new AtomicReference<>();
                MaxmindService.getInstance().submitTask(databaseReader -> {
                    try {
                        AsnResponse asn = databaseReader.asn(inetAddress);
                        if (BLACKLISTED_ASN_NUMBERS.contains(asn.getAutonomousSystemNumber())) {
                            blacklistedAsn.set(true); // IP has a blacklisted ASN
                            asnRisk.set(0.4f);
                        }
                    } catch (IOException | GeoIp2Exception ex) {
                        ex.printStackTrace();
                    }
                });
                return asnRisk.get();
            });
            
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
                blacklistedAsn.get(),
                false,
                false
            );
        }
    }
}
