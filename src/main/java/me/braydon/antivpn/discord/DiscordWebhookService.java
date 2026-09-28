package me.braydon.antivpn.discord;

import jakarta.annotation.PreDestroy;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.model.AddressData;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Posts lookup results to a Discord webhook, if one is configured.
 *
 * @author Braydon
 */
@Service
@Slf4j(topic = "Discord")
public class DiscordWebhookService {
    private static final Pattern WEBHOOK_PATH = Pattern.compile("/api(?:/v\\d+)?/webhooks/\\d+/[A-Za-z0-9._-]+/?");
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10L);
    
    @NonNull private final DiscordProperties properties;
    private final String webhookUrl;
    private final ExecutorService executor;
    
    public DiscordWebhookService(@NonNull DiscordProperties properties) {
        this.properties = properties;
        String configured = properties.getWebhookUrl() == null ? "" : properties.getWebhookUrl().trim();
        if (configured.isEmpty()) {
            this.webhookUrl = null;
            this.executor = null;
            return;
        }
        if (!isValidWebhookUrl(configured)) {
            log.warn("discord.webhook-url is set but is not a Discord webhook, logging is disabled");
            this.webhookUrl = null;
            this.executor = null;
            return;
        }
        this.webhookUrl = configured;
        this.executor = new ThreadPoolExecutor(
            1, 1,
            0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(256),
            runnable -> {
                Thread thread = new Thread(runnable, "discord-webhook");
                thread.setDaemon(true);
                return thread;
            },
            (task, pool) -> log.warn("Dropping a Discord lookup log, the queue is full")
        );
        log.info("Lookup results will be sent to Discord ({})", mask(configured));
    }
    
    /**
     * Whether a valid webhook is configured.
     *
     * @return true if lookups will be posted
     */
    public boolean isEnabled() {
        return webhookUrl != null;
    }
    
    /**
     * Queue a lookup result to be posted to Discord.
     * <p>
     * Does nothing if Discord logging is disabled, or if the
     * lookup's risk is below {@code discord.min-risk}. Failures
     * talking to Discord are logged and never affect the API response.
     * </p>
     *
     * @param data     the lookup result
     * @param metadata optional request metadata
     */
    public void logLookup(@NonNull AddressData data, Map<String, String> metadata) {
        if (!shouldLog(data)) {
            return;
        }
        String body = DiscordWebhookPayload.lookup(properties.getUsername(), data, metadata);
        executor.execute(() -> post(body));
    }
    
    /**
     * Whether this lookup should be posted.
     *
     * @param data the lookup result
     * @return true if it should be posted
     */
    public boolean shouldLog(@NonNull AddressData data) {
        return isEnabled() && data.getRisk() >= properties.getMinRisk();
    }
    
    /**
     * Check whether the given URL is a Discord webhook.
     *
     * @param url the URL
     * @return true if it looks like a Discord webhook
     */
    public static boolean isValidWebhookUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (!host.equals("discord.com") && !host.equals("discordapp.com")
                && !host.equals("canary.discord.com") && !host.equals("ptb.discord.com")) {
            return false;
        }
        return uri.getPath() != null && WEBHOOK_PATH.matcher(uri.getPath()).matches();
    }
    
    @NonNull
    static String mask(@NonNull String url) {
        int slash = url.lastIndexOf('/');
        return slash < 0 ? url : url.substring(0, slash + 1) + "***";
    }
    
    @PreDestroy
    void shutdown() {
        if (executor != null) {
            executor.shutdown();
        }
    }
    
    private void post(@NonNull String body) {
        try {
            HttpResponse<String> response = send(body);
            if (response.statusCode() == 429) {
                sleep(retryAfter(response));
                response = send(body);
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                log.warn("Discord webhook returned {}", response.statusCode());
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (Exception ex) {
            log.warn("Failed to post lookup to Discord: {}", ex.toString());
        }
    }
    
    @NonNull
    private HttpResponse<String> send(@NonNull String body) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                                    .uri(URI.create(webhookUrl))
                                    .timeout(REQUEST_TIMEOUT)
                                    .header("Content-Type", "application/json")
                                    .header("User-Agent", "AntiVPN (+https://github.com/Rainnny7/AntiVPN)")
                                    .POST(HttpRequest.BodyPublishers.ofString(body))
                                    .build();
        return AntiVPN.HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    }
    
    private static long retryAfter(@NonNull HttpResponse<String> response) {
        return response.headers().firstValue("Retry-After")
                   .map(value -> {
                       try {
                           return Math.clamp(Long.parseLong(value.trim()), 1L, 30L);
                       } catch (NumberFormatException ex) {
                           return 1L;
                       }
                   })
                   .orElse(1L);
    }
    
    private static void sleep(long seconds) throws InterruptedException {
        TimeUnit.SECONDS.sleep(seconds);
    }
}
