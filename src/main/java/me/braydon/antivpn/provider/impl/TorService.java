package me.braydon.antivpn.provider.impl;

import lombok.NonNull;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for Tor.
 *
 * @author Braydon
 */
@Service
public final class TorService extends VPNServiceProvider {
    private static final String GET_EXIT_NODES_ENDPOINT = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"; // Getting exit nodes
    
    /**
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    @Autowired
    public TorService(@NonNull JedisConnectionFactory jedisFactory) {
        super("Tor", TimeUnit.DAYS.toMillis(7L));
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
        // Add a scrape task to get all exit nodes
        addScrapeTask(new TimedScrapeTask("Fetch Exit Nodes", TimeUnit.MINUTES.toMillis(30L), () -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(URI.create(GET_EXIT_NODES_ENDPOINT))
                                          .GET()
                                          .timeout(Duration.ofSeconds(20L))
                                          .build();
                HttpResponse<InputStream> response = AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofInputStream());
                if (response.statusCode() != 200) { // If the status code is not 200
                    throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
                }
                try (InputStream inputStream = response.body();
                     InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                     BufferedReader bufferedReader = new BufferedReader(inputStreamReader)
                ) {
                    bufferedReader.lines() // Stream over the lines
                        .parallel() // Process in parallel
                        .forEach(ip -> addIp(jedisFactory, ip)); // Add the IP address
                }
            } catch (IOException | InterruptedException ex) {
                ex.printStackTrace();
            }
        }));
    }
}
