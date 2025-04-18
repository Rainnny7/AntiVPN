package me.braydon.antivpn.provider.impl;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import lombok.NonNull;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.provider.ServiceProvider;
import me.braydon.antivpn.provider.scrape.TimedScrapeTask;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * This VPN provider is for Cloudflare.
 *
 * @author Braydon
 */
@Service
public final class SpamhausService extends ServiceProvider {
    private static final String DROP_ENDPOINT = "https://www.spamhaus.org/drop/drop.txt"; // Drop list
    private static final String EDROP_ENDPOINT = "https://www.spamhaus.org/drop/edrop.txt"; // EDrop list
    private static final String DROPV6_ENDPOINT = "https://www.spamhaus.org/drop/dropv6.txt"; // DropV6 list
    
    public SpamhausService() {
        super(5, "Spamhaus", TimeUnit.DAYS.toMillis(7L));
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
        // Add a scrape task to get the drop list
        addScrapeTask(new TimedScrapeTask("Fetch Drop List", TimeUnit.HOURS.toMillis(3L), () -> {
            getList(DROP_ENDPOINT).parallelStream().forEach(this::addIp); // Add the IP addresses to the set
        }));
        
        // Add a scrape task to get the edrop list
        addScrapeTask(new TimedScrapeTask("Fetch EDrop List", TimeUnit.HOURS.toMillis(3L), () -> {
            getList(EDROP_ENDPOINT).parallelStream().forEach(this::addIp); // Add the IP addresses to the set
        }));
        
        // Add a scrape task to get the eropv6 list
        //        addScrapeTask(new TimedScrapeTask("Fetch DropV6 List", TimeUnit.HOURS.toMillis(3L), () -> {
        //            getList(DROPV6_ENDPOINT).parallelStream().forEach(this::addIp)); // Add the IP addresses to the set
        //        }));
    }
    
    /**
     * Get a list of IP addresses from an endpoint.
     *
     * @param endpoint the endpoint
     * @return the list of ips
     */
    @NonNull
    private Collection<String> getList(@NonNull String endpoint) {
        String body = WebRequest.builder()
                          .url(endpoint)
                          .build()
                          .send(HttpResponse.BodyHandlers.ofString()); // Send a request to the IPv4 endpoint
        return Arrays.stream(body.split("\n")) // Stream over the returned ranges
                   .parallel() // Process in parallel
                   .filter(line -> !line.startsWith(";")) // Filter out comments
                   .map(line -> line.split(";")[0].trim()) // Extract the range
                   .flatMap(range -> new IPAddressString(range).getAddress() // Get the IP address range
                                         .toPrefixBlock() // Convert the range to a prefix block
                                         .withoutPrefixLength() // Remove the prefix length
                                         .stream()) // Stream over the IP addresses in the range
                   .map(IPAddress::toString) // Convert the IP addresses to strings
                   .collect(Collectors.toList()); // Collect the IP addresses to a list
    }
}
