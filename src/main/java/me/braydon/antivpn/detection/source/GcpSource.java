package me.braydon.antivpn.detection.source;

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
 * Google Cloud's published customer IP ranges.
 * <p>
 * This is only Google Cloud, not Google's own services,
 * which are shared with consumer products like Google Fi.
 * </p>
 *
 * @author Braydon
 */
@Component
public final class GcpSource extends DetectionSource {
    private static final String ENDPOINT = "https://www.gstatic.com/ipranges/cloud.json";
    
    public GcpSource() {
        super("gcp", "Google Cloud", Category.HOSTING, Confidence.CONFIRMED, Duration.ofHours(24L));
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
        List<String> entries = new ArrayList<>();
        for (JsonElement element : AntiVPN.GSON.fromJson(json, JsonObject.class).getAsJsonArray("prefixes")) {
            JsonObject prefix = element.getAsJsonObject();
            for (String key : new String[] { "ipv4Prefix", "ipv6Prefix" }) {
                JsonElement value = prefix.get(key);
                if (value != null && !value.isJsonNull()) {
                    entries.add(value.getAsString());
                }
            }
        }
        return entries;
    }
}
