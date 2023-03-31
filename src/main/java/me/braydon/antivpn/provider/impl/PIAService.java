package me.braydon.antivpn.provider.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.NonNull;
import lombok.SneakyThrows;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.provider.VPNServiceProvider;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.Level;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This VPN provider is for Private Internet Access.
 *
 * @author Braydon
 */
@Component
public final class PIAService extends VPNServiceProvider {
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                                                      .followRedirects(HttpClient.Redirect.ALWAYS)
                                                      .build(); // The HTTP client to use
    private static final String LOGIN_PAGE = "https://www.privateinternetaccess.com/account/client-sign-in";
    private static final String LOGIN_ENDPOINT = "https://www.privateinternetaccess.com/account/ccp-sign-in";
    private static final String GET_SERVERS_ENDPOINT = "https://serverlist.piaservers.net/vpninfo/servers/v6";
    private static final String GENERATE_CONFIG_PAGE = "https://www.privateinternetaccess.com/account/ovpn-config-generator";
    private static final String GENERATE_CONFIG_ENDPOINT = "https://www.privateinternetaccess.com/account/ovpn-config-generator/generate";
    private static final String CSRF_HEADER = "authenticity_token";
    private static final String CSRF_KEY = "csrf-token";
    private static final String SESSION_COOKIE_NAME = "__pia_session";
    
    /**
     * The username to login to the PIA account.
     */
    @Value("${services.pia.user}")
    private String accountUsername;
    
    /**
     * The password to login to the PIA account.
     */
    @Value("${services.pia.pass}")
    private String accountPassword;
    
    /**
     * The amount of threads to use for our thread pool.
     */
    @Value("${services.pia.threads}")
    private int threads;
    
    /**
     * The thread pool used for running parallel tasks.
     *
     * @see ExecutorService for thread pool
     */
    private ExecutorService threadPool;
    
    /**
     * The regions for this provider.
     * <p>
     * The key is the region id, and the
     * value is the dns for the region.
     * </p>
     */
    @NonNull private final Map<String, String> regions = Collections.synchronizedMap(new HashMap<>());
    
    public PIAService() {
        super("Private Internet Access");
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
        threadPool = Executors.newFixedThreadPool(threads); // The thread pool to use for scraping
        
        System.out.println("accountUsername = " + accountUsername);
        System.out.println("accountPassword = " + accountPassword);
        
        // Add a scrape task to get all server regions
        addScrapeTask(new TimedScrapeTask(TimeUnit.MINUTES.toMillis(10L), () -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                                          .uri(new URI(GET_SERVERS_ENDPOINT))
                                          .GET()
                                          .timeout(Duration.ofSeconds(5L))
                                          .build();
                HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) { // If the status code is not 200
                    throw new IllegalStateException(String.format("Invalid error code (%s) returned when trying to get server regions",
                        response.statusCode()
                    ));
                }
                String body = response.body(); // The json
                String json = body.split("\n")[0]; // Get the top half of the body
                
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
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }));
        
        // Add a scrape task to perform a DNS lookup of all A records for all regions
//        addScrapeTask(new TimedScrapeTask(TimeUnit.MINUTES.toMillis(2L), () -> {
//            for (String dns : regions.values()) {
//                threadPool.submit(() -> {
//                    Record[] records;
//                    try {
//                        records = new Lookup(dns, Type.A).run();
//                        for (Record record : records) {
//                            String value = record.rdataToString(); // The value of the record
//                            addIp(value, "DNS Lookup - " + dns); // Add the IP address
//                        }
//                    } catch (TextParseException ex) {
//                        throw new RuntimeException(ex);
//                    }
//                });
//            }
//        }));
        
        // Add a scrape task to add all IPs in the downloaded OpenVPN config files
        addScrapeTask(new TimedScrapeTask(TimeUnit.DAYS.toMillis(1L), () -> {
//            String sessionCookie = "85KzypdGEuyyKJIMF0lpTLUC86GXrAHfcdPCa8NM9SL8XswoWA4qJ9MYjZ0KeNkyU4QwTG8%2BHsDkmBLTwrkEDYW0H49%2F3MLWz7TVrOGotfZ%2BxamS5ksukij3sZHiwNpCAsu6XNbvOSWrjFi3EsF%2F8ax%2BFatH1w1hPGQkkQbNLYn7JdDF0qhCurlRKmSBMDYtcg1qyUiqd1DTH1E0il70MD5GzWYh4r4PtKxLfAAPLCSvTgjI3oiD4j1h7mC%2F%2F4HslWyG3NWdZB6%2BG0dcgfymYwccpyKKvUifA16g08kE%2Bo%2FHj4%2BaBBcNLMwK9zR%2FPVCusNu6H6vtSTfZdkRrT7qXQsN9CWpc%2F0MAQJg53T8WDjiAGQmNstlcLDXVNM4j9A%2Fmyk5EeTERYChm9I12yzSaA7QVVg6MpXWwMjXWZSqdx98TR%2Bz5VplPMvoRS%2F%2BOR4xDIMMr4ZZfp3GQ--TfeRmOEwteCKHT1K--wohHiS5uzr42SSFc9nbNwg%3D%3D"; // Auth and get the session cookie
            String sessionCookie = "ID7RvVhIBY7NpTHzLHqHDXrkHY4xoCIX4G8uzc7vDZY8mamNL5sXbJ%2BuqzyQDOpO6r5csK%2Bkqb7CEXIS1k1cHX%2FFV8enXE0ryIR8ZKsIEGaFyW3%2BYVImkvD7pepo7zyggq7u1F%2BMmQn26%2FZA2gJMdXtD1JIZzrqWUu%2FmxCv5w4wpPJiSWOAe0lTTVnF0WQDuc7clBb8dqdi8txdnMXmphqWpSww%2FD1yXi7jes1hSxabtGUn2CdS7b%2F%2Bi%2FoAT7%2Fo9h6Y7kwM6qj8ulMX0J0xRSHdZvTCBLnQlqJRnf2r6KRy6%2FouJN%2FJbmNR742Dz6HNwSAaZAlqH2Vap3ggQ6xAReDHwBFSyVSH%2BW08cis4GGDDYZIg6xUQRAM4rPBzpMLqFfXhwpwKxYo%2Fkks1oKVAN71UqgoP9gr2vtxAtdXreOEYUxE2WhQkqUQEVcdDBwPqMnGMFXDx4Tqbf--FkINuEWVSeCdMnjh--IkCXCV56YJCcRfh6CrrupQ%3D%3D"; // Auth and get the session cookie
            String csrfToken = "xZNI9yie9pa3QNM1qk8ZvuITE/VECAEvFe0XbNBMRSUM6jk1cX5lA8ErrrmT5TCVMAcqZle9TV7rDbr6fgyoFQ=="; // Get the CSRF token to generate a config
            System.out.println("sessionCookie = " + sessionCookie);
            System.out.println("csrfToken = " + csrfToken);
//            HtmlUtils.htmlEscape(sessionCookie);
            
            AtomicInteger regionsScraped = new AtomicInteger(); // The amount of regions scraped
            for (String region : regions.keySet()) {
                threadPool.submit(() -> {
                    try {
                        log("Scraping region '{}' OpenVPN config files...", region); // Log the scrape of the region
                        
                        // Send the request to get the config
                        String body = String.format("%s=%s" +
                                                        "&target_version=2.4" +
                                                        "&platform=desktop" +
                                                        "&nextgen_region=%s" +
                                                        "&cipher=aes-128-cbc" +
                                                        "&protocol=udp" +
                                                        "&type=aes-128-cbc-udp" +
                                                        "&port=" +
                                                        "&ip=1" +
                                                        "&button=",
                            CSRF_HEADER,
                            csrfToken,
                            region
                        );
                        HttpRequest request = HttpRequest.newBuilder()
                                                  .uri(new URI(GENERATE_CONFIG_ENDPOINT))
                                                  .POST(HttpRequest.BodyPublishers.ofString(body))
                                                  .timeout(Duration.ofSeconds(5L))
                                                  .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
                                                  .header("Accept-Language", "en-US,en;q=0.5")
                                                  .header("Content-Type", "application/x-www-form-urlencoded")
                                                  .header("Cache-Control", "no-cache")
                                                  .header("Cache-Control", "no-cache")
                                                  .header("Cookie", SESSION_COOKIE_NAME + "=" + sessionCookie)
                                                  .build();
                        int found = 0; // The amount of config files found for this region
                        for (int i = 0; i < 2000; i++) { // Attempt to get 1000 unique config files
                            try {
                                HttpResponse<InputStream> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofInputStream());
                                if (response.statusCode() != 200) { // If the status code is not 200
                                    throw new IllegalStateException(String.format("Invalid error code (%s) returned when trying to download OpenVPN config",
                                        response.statusCode()
                                    ));
                                }
                                // Handle scraping
                                List<String> lines = Arrays.asList(IOUtils.toString(response.body(),
                                    StandardCharsets.UTF_8).split("\n")); // The lines of the downloaded config file
                                try {
                                    String ip = lines.get(3).split(" ")[1]; // The IP address of the server in the config
                                    if (!hasIp(ip)) { // Increment the found count
                                        addIp(ip, "OpenVPN Config"); // Add the IP address
                                        found++; // Increment the found count
                                    }
                                } catch (ArrayIndexOutOfBoundsException ex) { // Response is not formatted properly
                                    log(Level.ERROR, "Response from config endpoint is invalid", ex);
                                }
                            } catch (Exception ex) { // Log any errors
                                log(Level.ERROR, "Failed scrape for region '{}'", region, ex);
                            }
                        }
                        // Log the amount of IP addresses found for the region
                        log("Found {} IP addresses for region '{}'", found, region);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    } finally {
                        int regions = regionsScraped.incrementAndGet(); // Regions scraped
                        log("Scraped {}/{} regions", regions, this.regions.size());
                    }
                });
            }
        }));
    }
    
    @NonNull
    private String auth() {
        log("Attempting to auth..."); // Log the auth attempt
        try {
            String csrfToken = getCsrfToken(LOGIN_PAGE);
            if (csrfToken == null) { // We need the CSRF token to login
                throw new NullPointerException("No CSRF token found");
            }
            System.out.println("csrfToken FOR LOGIN = " + csrfToken);
            log("Found CSRF data, logging in..."); // Log the finding of the CSRF data and the login attempt
            
            // Sending a POST request to the login endpoint so we can get the cookie session
            String body = String.format("screen_height=1206&screen_width=2144&user=%s&pass=%s&%s=%s",
                accountUsername,
                accountPassword,
                CSRF_HEADER,
                csrfToken
            );
            HttpRequest request = HttpRequest.newBuilder()
                                      .uri(new URI(LOGIN_ENDPOINT))
                                      .POST(HttpRequest.BodyPublishers.ofString(body))
                                      .timeout(Duration.ofSeconds(5L))
                                      .build();
            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString()); // Send the response
            HttpHeaders headers = response.headers();
            List<String> cookieValues = headers.allValues("set-cookie"); // The cookies from the response
            
            // Extract the cookie session from the login response
            for (String cookieValue : cookieValues) {
                if (!cookieValue.contains(SESSION_COOKIE_NAME)) { // Not the right cookie
                    continue;
                }
                String sessionCookie = cookieValue.split("=")[1];
                sessionCookie = sessionCookie.substring(0, sessionCookie.lastIndexOf(";"));
                
                log("Successfully authenticated"); // Log the successful authentication
                return sessionCookie; // Return the session cookie
            }
        } catch (IOException | URISyntaxException | InterruptedException ex) {
            ex.printStackTrace();
        }
        throw new IllegalStateException("Failed to authenticate"); // Failed?
    }
    
    /**
     * Get the CSRF token from the given url.
     *
     * @param url the url
     * @return the csrf token, null if none
     */
    private String getCsrfToken(@NonNull String url) {
        log("Retrieving CSRF token from {}", url); // Log the retrieval of the CSRF token
        try {
            // Sending a request to the login page to generate the csrf header and token
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                              .uri(new URI(url))
                                              .GET()
                                              .timeout(Duration.ofSeconds(5L));
            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) { // If the status code is not 200
                throw new IllegalStateException(String.format("Invalid error code (%s) returned when trying to get CSRF token",
                    response.statusCode()
                ));
            }
            // Parsing the returned html
            String html = response.body(); // The html
            Document document = Jsoup.parse(html);
            Element htmlElement = document.selectFirst("html");
            if (htmlElement == null) { // wut
                throw new NullPointerException("Could not find 'html' element inside of html");
            }
            Element headElement = htmlElement.selectFirst("head");
            if (headElement == null) { // wut again
                throw new NullPointerException("Could not find 'head' element inside of html");
            }
            String csrfToken = null;
            for (Element metaElement : headElement.select("meta")) {
                String name = metaElement.attr("name"); // The name of the meta element
                String content = metaElement.attr("content"); // The content of the attribute
                if (name.equals(CSRF_KEY)) {
                    csrfToken = content;
                    break;
                }
            }
            if (csrfToken == null) { // We kind of needs these x.x
                throw new NullPointerException("Could not find CSRF header and/or token");
            }
            log("Found CSRF token from '{}'", url); // Log that we found the CSRF token
            return csrfToken;
        } catch (IOException | URISyntaxException | InterruptedException ex) {
            ex.printStackTrace();
        }
        return null;
    }
}