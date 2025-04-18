package me.braydon.antivpn.provider.impl;

import lombok.NonNull;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.StringUtils;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.provider.ServiceProvider;
import me.braydon.antivpn.provider.scrape.TimedScrapeTask;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.net.http.HttpResponse;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for NordVPN.
 *
 * @author Braydon
 */
@Service
public final class NordService extends ServiceProvider {
    private static final String CONFIGS_PAGE = "https://nordvpn.com/ovpn/";
    private static final String DNS_REGEX = "^[^.]+\\.nordvpn\\.com$"; // The DNS server regex pattern
    
    /**
     * The DNS servers of this provider.
     */
    @NonNull private Set<String> dns = new HashSet<>();
    
    public NordService() {
        super(2, "NordVPN", TimeUnit.DAYS.toMillis(7L));
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
            String html = WebRequest.builder()
                              .url(CONFIGS_PAGE)
                              .build()
                              .send(HttpResponse.BodyHandlers.ofString()); // Send a request to the configs page
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
                    IPUtils.getIpFromHostname(dns, this::addIp);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            });
        }));
    }
}