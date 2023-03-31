package me.braydon.antivpn.provider.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.NonNull;
import lombok.SneakyThrows;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * This VPN provider is for Private Internet Access.
 *
 * @author Braydon
 */
@Component
public final class PIAService extends VPNServiceProvider {
    private static final String GITHUB_REPO = "Lars-/PIA-servers"; // The GitHub repository to scrape for server IPs
    private static final String GET_SERVERS_ENDPOINT = "https://serverlist.piaservers.net/vpninfo/servers/v6"; // Getting server regions/dns
    private static final String MASTER_TREES_ENDPOINT = String.format("https://api.github.com/repos/%s/git/trees/master", GITHUB_REPO); // Getting tree list
    private static final String TREE_CONTENTS_ENDPOINT = String.format("https://api.github.com/repos/%s/git/trees", GITHUB_REPO); // Getting tree contents
    private static final String SERVERS_DIR = "docs"; // The directory in the repo contains a list of ips for this provider
    
    /**
     * The bearer token to auth with GitHub.
     */
    @Value("${github.bearer}")
    private String githubBearer;
    
    /**
     * The version of the GitHub API to use.
     */
    @Value("${github.api-version}")
    private String githubApiVersion;
    
    /**
     * The regions for this provider.
     * <p>
     * The key is the region id, and the
     * value is the dns for the region.
     * </p>
     */
    @NonNull private final Map<String, String> regions = Collections.synchronizedMap(new HashMap<>());
    
    public PIAService() {
        super("Private Internet Access", TimeUnit.DAYS.toMillis(14L));
    }
    
    /**
     * Initialize this provider.
     * <p>
     * This will get the ids of all
     * regions for this provider.
     * </p>
     */
    @PostConstruct @SneakyThrows
    public void initialize() {
        // Add a scrape task to get all server regions
        addScrapeTask(new TimedScrapeTask(TimeUnit.MINUTES.toMillis(10L), () -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(URI.create(GET_SERVERS_ENDPOINT))
                                          .GET()
                                          .timeout(Duration.ofSeconds(5L))
                                          .build();
                HttpResponse<String> response = AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) { // If the status code is not 200
                    throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
                }
                String body = response.body(); // The body of the response
                String json = body.split("\n")[0]; // Get the top half of the body, that's the json
                
                JsonObject jsonObject = AntiVPN.GSON.fromJson(json, JsonObject.class);
                for (JsonElement regionJsonElement : jsonObject.get("regions").getAsJsonArray()) {
                    JsonObject regionJsonObject = regionJsonElement.getAsJsonObject();
                    if (regionJsonObject.get("offline").getAsBoolean()) { // Skip offline regions
                        continue;
                    }
                    String id = regionJsonObject.get("id").getAsString(); // The id of the region
                    String dns = regionJsonObject.get("dns").getAsString(); // The dns of the region
                    regions.put(id, dns);
                }
                // Log the loaded regions
                log("Found {} regions: {}", regions.size(), String.join(", ", regions.keySet()));
            } catch (IOException | InterruptedException ex) {
                ex.printStackTrace();
            }
        }));
        
        // Add a scrape task to perform a DNS lookup of all A records for all regions
        addScrapeTask(new TimedScrapeTask(TimeUnit.MINUTES.toMillis(2L), () -> {
            for (String dns : regions.values()) {
                VPNServiceProvider.THREAD_POOL.submit(() -> {
                    Record[] records;
                    try {
                        records = new Lookup(dns, Type.A).run();
                        if (records == null) { // Error when retrieving DNS records
                            throw new NullPointerException(String.format("Could not retrieve DNS records for '%s'", dns));
                        }
                        for (Record record : records) {
                            String value = record.rdataToString(); // The value of the record
                            addIp(value, "DNS Lookup - " + dns); // Add the IP address
                        }
                    } catch (TextParseException ex) {
                        throw new RuntimeException(ex);
                    }
                });
            }
        }));
        
        // Add a scrape task to add all IPs found from the GitHub
        // repository that contains a list of IPs for this provider
        addScrapeTask(new TimedScrapeTask(TimeUnit.DAYS.toMillis(1L), () -> {
            // Send a request to get the tree list
            String sha = null; // The sha of the directory that contains the server ips
            for (JsonObject treeEntry : getRepositoryTree(MASTER_TREES_ENDPOINT)) {
                String path = treeEntry.get("path").getAsString(); // The path of the tree
                if (!path.equals(SERVERS_DIR)) { // Not the directory we need
                    continue;
                }
                sha = treeEntry.get("sha").getAsString(); // The sha of the tree entry
                break;
            }
            if (sha == null) { // No sha found
                throw new NullPointerException("Could not get the SHA of the servers directory");
            }
            for (JsonObject treeEntry : getRepositoryTree(TREE_CONTENTS_ENDPOINT + "/" + sha)) {
                String path = treeEntry.get("path").getAsString(); // The path of the tree
                addIp(path, "GitHub Repo"); // Add the IP address
            }
        }));
    }
    
    /**
     * Send a web request to the
     * given GitHub API endpoint.
     *
     * @param endpoint the endpoint
     * @return the json response
     */
    @NonNull
    private Set<JsonObject> getRepositoryTree(@NonNull String endpoint) {
        Set<JsonObject> tree = new HashSet<>();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                                      .uri(URI.create(endpoint))
                                      .GET()
                                      .timeout(Duration.ofSeconds(5L))
                                      .header("Accept", "application/vnd.github+json")
                                      .header("X-GitHub-Api-Version", githubApiVersion)
                                      .header("Authorization", "Bearer " + githubBearer)
                                      .build();
            HttpResponse<String> response = AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) { // If the status code is not 200
                throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
            }
            JsonObject jsonObject = AntiVPN.GSON.fromJson(response.body(), JsonObject.class);
            for (JsonElement treeElement : jsonObject.getAsJsonArray("tree")) {
                tree.add(treeElement.getAsJsonObject());
            }
        } catch (IOException | InterruptedException ex) {
            ex.printStackTrace();
        }
        return Collections.unmodifiableSet(tree);
    }
}