package me.braydon.antivpn.provider.impl;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
    
    public CloudflareService() {
        super("Cloudflare", TimeUnit.DAYS.toMillis(7L));
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
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(URI.create(GET_IPV4_ENDPOINT))
                                          .GET()
                                          .timeout(Duration.ofSeconds(20L))
                                          .build();
                HttpResponse<String> response = AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) { // If the status code is not 200
                    throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
                }
                String body = response.body(); // The body of the response
                Arrays.stream(body.split("\n")) // Stream over the returned ranges
                    .parallel() // Process in parallel
                    .flatMap(range -> new IPAddressString(range).getAddress() // Get the IP address range
                                          .toPrefixBlock() // Convert the range to a prefix block
                                          .withoutPrefixLength() // Remove the prefix length
                                          .stream()) // Stream over the IP addresses in the range
                    .map(IPAddress::toString) // Convert the IP addresses to strings
                    .forEach(this::addIp); // Add the IP address
            } catch (IOException | InterruptedException ex) {
                ex.printStackTrace();
            }
        }));
    }
}
