package me.braydon.antivpn.provider.impl;

import lombok.NonNull;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.StringUtils;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for NordVPN.
 *
 * @author Braydon
 */
@Service
public final class NordService extends VPNServiceProvider {
    private static final String CONFIGS_PAGE = "https://nordvpn.com/ovpn/";
    private static final String DNS_REGEX = "^[^.]+\\.nordvpn\\.com$"; // The DNS server regex pattern
    
    /**
     * The DNS servers of this provider.
     */
    @NonNull private Set<String> dns = new HashSet<>();
    
    /**
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    @Autowired
    public NordService(@NonNull JedisConnectionFactory jedisFactory) {
        super("NordVPN", TimeUnit.DAYS.toMillis(7L));
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
        // Add a scrape task to get all dns servers
        addScrapeTask(new TimedScrapeTask("Fetch DNS Servers", TimeUnit.HOURS.toMillis(3L), () -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(URI.create(CONFIGS_PAGE))
                                          .GET()
                                          .timeout(Duration.ofSeconds(20L))
                                          .build();
                HttpResponse<String> response = AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) { // If the status code is not 200
                    throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
                }
                String html = response.body(); // The html of the response
                Document document = Jsoup.parse(html);
                
                Set<String> dns = new HashSet<>(); // The new DNS servers
                for (Element serverElement : document.getElementsContainingText("nordvpn.com")) {
                    for (Element spanElement : serverElement.getElementsByClass("mr-2")) {
                        if (!spanElement.nodeName().equals("span")) { // Not the element we're looking for
                            continue;
                        }
                        String text = spanElement.text();
                        if (!text.matches(DNS_REGEX)) { // Value of the element is not a DNS server
                            continue;
                        }
                        dns.add(text); // Add the DNS server
                    }
                }
                this.dns = dns; // Update the DNS actual list
                
                // Log the DNS servers
                log("Found {} DNS servers", StringUtils.formatNumber(dns.size()));
            } catch (IOException | InterruptedException ex) {
                ex.printStackTrace();
            }
        }));
        
        // Add a scrape task to perform a DNS lookup of all A records for DNS servers
        addScrapeTask(new TimedScrapeTask("DNS Lookup", TimeUnit.MINUTES.toMillis(2L), () -> {
            if (dns.isEmpty()) { // No DNS servers found
                log("No DNS servers found, skipping DNS lookup");
                return;
            }
            // Add the IP to the list
            dns.parallelStream().forEach(dns -> {
                try {
                    IPUtils.getIpFromDns(dns, ip -> addIp(jedisFactory, ip));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            });
        }));
    }
}