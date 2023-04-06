package me.braydon.antivpn.provider.impl;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import lombok.NonNull;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for Cloudflare.
 *
 * @author Braydon
 */
@Service
public final class CloudflareService extends VPNServiceProvider {
    private static final String GET_IPV4_ENDPOINT = "https://www.cloudflare.com/ips-v4"; // Getting IPv4 addresses
    
    /**
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    @Autowired
    public CloudflareService(@NonNull JedisConnectionFactory jedisFactory, @NonNull MetricService metrics) {
        super("Cloudflare", TimeUnit.DAYS.toMillis(7L), metrics);
        this.jedisFactory = jedisFactory;
    }
    
    /**
     * Initialize this provider.
     * <p>
     * This will get the ids of all
     * regions for this provider.
     * </p>
     */
    @PostConstruct
    public void initialize() {
        // Add a scrape task to get all provider ips
        addScrapeTask(new TimedScrapeTask("Fetch IPv4 List", TimeUnit.DAYS.toMillis(1L), () -> {
            String body = WebRequest.builder()
                              .url(GET_IPV4_ENDPOINT)
                              .build()
                              .send(HttpResponse.BodyHandlers.ofString()); // Send a request to the IPv4 endpoint
            Arrays.stream(body.split("\n")) // Stream over the returned ranges
                .parallel() // Process in parallel
                .flatMap(range -> new IPAddressString(range).getAddress() // Get the IP address range
                                      .toPrefixBlock() // Convert the range to a prefix block
                                      .withoutPrefixLength() // Remove the prefix length
                                      .stream()) // Stream over the IP addresses in the range
                .map(IPAddress::toString) // Convert the IP addresses to strings
                .forEach(ip -> addIp(jedisFactory, ip)); // Add the IP address
        }));
    }
}
