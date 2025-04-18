package me.braydon.antivpn.provider.impl;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.provider.ServiceProvider;
import me.braydon.antivpn.provider.scrape.TimedScrapeTask;
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
public final class CloudflareService extends ServiceProvider {
    private static final String GET_IPV4_ENDPOINT = "https://www.cloudflare.com/ips-v4"; // Getting IPv4 addresses
    
    public CloudflareService() {
        super(3, "Cloudflare", TimeUnit.DAYS.toMillis(7L));
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
                .forEach(this::addIp); // Add the IP address
        }));
    }
}
