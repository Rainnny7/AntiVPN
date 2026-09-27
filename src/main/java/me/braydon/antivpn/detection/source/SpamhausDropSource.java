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
 * Spamhaus DROP (Don't Route Or Peer), netblocks that are
 * hijacked or leased by professional spam or cyber-crime operations.
 * <p>
 * The former EDROP list is merged into DROP.
 * </p>
 *
 * @author Braydon
 */
@Component
public final class SpamhausDropSource extends DetectionSource {
    private static final String[] ENDPOINTS = {
        "https://www.spamhaus.org/drop/drop_v4.json",
        "https://www.spamhaus.org/drop/drop_v6.json"
    };
    
    public SpamhausDropSource() {
        super("spamhaus-drop", "Spamhaus DROP", Category.ABUSE, Confidence.CONFIRMED, Duration.ofHours(12L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        List<String> entries = new ArrayList<>();
        for (String endpoint : ENDPOINTS) {
            entries.addAll(parse(WebRequest.builder().url(endpoint).build().sendAsString()));
        }
        return entries;
    }
    
    /**
     * Parse a DROP list, one JSON object per line.
     * <p>
     * The trailing metadata line has no {@code cidr} and is skipped.
     * </p>
     *
     * @param body the list
     * @return the netblocks
     */
    @NonNull
    public static List<String> parse(@NonNull String body) {
        List<String> entries = new ArrayList<>();
        for (String line : body.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            JsonElement cidr = AntiVPN.GSON.fromJson(line, JsonObject.class).get("cidr");
            if (cidr != null && !cidr.isJsonNull()) {
                entries.add(cidr.getAsString());
            }
        }
        return entries;
    }
}
