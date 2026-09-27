package me.braydon.antivpn.detection.source;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.NonNull;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.DetectionSource;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Amazon Web Services' published IP ranges.
 *
 * @author Braydon
 */
@Component
public final class AwsSource extends DetectionSource {
    private static final String ENDPOINT = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    
    public AwsSource() {
        super("aws", "Amazon Web Services", Category.HOSTING, Confidence.CONFIRMED, Duration.ofHours(24L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        return parse(WebRequest.builder().url(ENDPOINT).build().sendAsString());
    }
    
    /**
     * Parse the IP ranges document.
     *
     * @param json the document
     * @return the ranges
     */
    @NonNull
    public static List<String> parse(@NonNull String json) {
        JsonObject root = AntiVPN.GSON.fromJson(json, JsonObject.class);
        List<String> entries = new ArrayList<>();
        collect(root.getAsJsonArray("prefixes"), "ip_prefix", entries);
        collect(root.getAsJsonArray("ipv6_prefixes"), "ipv6_prefix", entries);
        return entries;
    }
    
    private static void collect(JsonArray prefixes, @NonNull String key, @NonNull List<String> entries) {
        if (prefixes == null) {
            return;
        }
        for (JsonElement element : prefixes) {
            JsonElement prefix = element.getAsJsonObject().get(key);
            if (prefix != null && !prefix.isJsonNull()) {
                entries.add(prefix.getAsString());
            }
        }
    }
}
