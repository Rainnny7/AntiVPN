package me.braydon.antivpn.provider.impl;

import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.provider.ServiceProvider;
import me.braydon.antivpn.provider.scrape.TimedScrapeTask;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for Tor.
 *
 * @author Braydon
 */
@Service
public final class TorService extends ServiceProvider {
    private static final String GET_EXIT_NODES_ENDPOINT = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"; // Getting exit nodes
    
    public TorService() {
        super(4, "Tor", TimeUnit.DAYS.toMillis(7L));
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
        addScrapeTask(new TimedScrapeTask("Fetch Exit Nodes", TimeUnit.HOURS.toMillis(3L), () -> {
            try {
                try (InputStream inputStream = WebRequest.builder()
                                                   .url(GET_EXIT_NODES_ENDPOINT)
                                                   .build()
                                                   .sendAsInputStream(); // Send a request to the exit nodes endpoint
                     InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                     BufferedReader bufferedReader = new BufferedReader(inputStreamReader)
                ) {
                    bufferedReader.lines() // Stream over the lines
                        .parallel() // Process in parallel
                        .forEach(this::addIp); // Add the IP address
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }));
    }
}
