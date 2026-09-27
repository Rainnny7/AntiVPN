package me.braydon.antivpn.detection.source;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.DetectionSource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Surfshark servers, from Surfshark's public cluster
 * list with each cluster hostname resolved over DNS.
 * <p>
 * Each lookup only returns some of a cluster's servers,
 * so addresses are kept for 14 days after they were last seen.
 * </p>
 *
 * @author Braydon
 */
@Component
@Slf4j(topic = "Surfshark")
public final class SurfsharkSource extends DetectionSource {
    private static final String ENDPOINT = "https://api.surfshark.com/v4/server/clusters/generic";
    
    public SurfsharkSource() {
        super("surfshark", "Surfshark", Category.VPN, Confidence.CONFIRMED, Duration.ofHours(1L));
    }
    
    @Override
    public Duration getRetention() {
        return Duration.ofDays(14L);
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        List<String> hostnames = parse(WebRequest.builder().url(ENDPOINT).build().sendAsString());
        List<String> entries = new ArrayList<>();
        int failures = 0;
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<List<String>>> lookups = new ArrayList<>();
            for (String hostname : hostnames) {
                lookups.add(executor.submit(() -> IPUtils.resolveHostname(hostname)));
            }
            for (Future<List<String>> lookup : lookups) {
                try {
                    entries.addAll(lookup.get());
                } catch (Exception ex) {
                    failures++;
                }
            }
        }
        if (failures > 0) {
            log.info("Failed to resolve {} of {} cluster hostnames", failures, hostnames.size());
        }
        if (entries.isEmpty() && !hostnames.isEmpty()) {
            throw new IOException("Could not resolve any of the " + hostnames.size() + " cluster hostnames");
        }
        return entries;
    }
    
    /**
     * Parse the cluster list, taking the {@code connectionName} of each cluster.
     *
     * @param json the cluster list
     * @return the cluster hostnames
     */
    @NonNull
    public static List<String> parse(@NonNull String json) {
        Set<String> hostnames = new LinkedHashSet<>();
        for (JsonElement element : AntiVPN.GSON.fromJson(json, JsonArray.class)) {
            JsonElement connectionName = element.getAsJsonObject().get("connectionName");
            if (connectionName != null && !connectionName.isJsonNull() && !connectionName.getAsString().isBlank()) {
                hostnames.add(connectionName.getAsString());
            }
        }
        return new ArrayList<>(hostnames);
    }
}
