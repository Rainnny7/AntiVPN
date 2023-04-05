package me.braydon.antivpn.provider.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.NonNull;
import lombok.SneakyThrows;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.StringUtils;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.stereotype.Service;

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
@Service
public final class PiaService extends VPNServiceProvider {
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
    
    /**
     * The jedis connection factory.
     *
     * @see JedisConnectionFactory for jedis connection factory
     */
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    @Autowired
    public PiaService(@NonNull JedisConnectionFactory jedisFactory, @NonNull MetricService metrics) {
        super("Private Internet Access", TimeUnit.DAYS.toMillis(14L), metrics);
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
    @SneakyThrows
    public void initialize() {
        // Add a scrape task to get all server regions
        addScrapeTask(new TimedScrapeTask("Fetch Regions", TimeUnit.MINUTES.toMillis(10L), () -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(URI.create(GET_SERVERS_ENDPOINT))
                                          .GET()
                                          .timeout(Duration.ofSeconds(20L))
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
                log("Found {} regions: {}", StringUtils.formatNumber(regions.size()), String.join(", ", regions.keySet()));
            } catch (IOException | InterruptedException ex) {
                ex.printStackTrace();
            }
        }));
        
        // Add a scrape task to perform a DNS lookup of all A records for all regions
        addScrapeTask(new TimedScrapeTask("DNS Lookup", TimeUnit.MINUTES.toMillis(2L), () -> {
            if (regions.isEmpty()) { // No DNS servers found
                log("No regions found, skipping DNS lookup");
                return;
            }
            // Add the IP to the list
            regions.values().parallelStream().forEach(dns -> {
                try {
                    IPUtils.getIpFromDns(dns, ip -> addIp(jedisFactory, ip));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            });
        }));
        
        // Add a scrape task to add all IPs found from the GitHub
        // repository that contains a list of IPs for this provider
        addScrapeTask(new TimedScrapeTask("Fetch GH Repo", TimeUnit.DAYS.toMillis(1L), () -> {
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
                addIp(jedisFactory, treeEntry.get("path").getAsString()); // Add the IP address
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
                                      .timeout(Duration.ofSeconds(20L))
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