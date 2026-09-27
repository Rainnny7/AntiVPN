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
 * Mullvad relays, from Mullvad's public relay API.
 *
 * @author Braydon
 */
@Component
public final class MullvadSource extends DetectionSource {
    private static final String ENDPOINT = "https://api.mullvad.net/www/relays/all/";
    
    public MullvadSource() {
        super("mullvad", "Mullvad", Category.VPN, Confidence.CONFIRMED, Duration.ofHours(6L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        return parse(WebRequest.builder().url(ENDPOINT).build().sendAsString());
    }
    
    /**
     * Parse the relay list, taking the addresses of active relays.
     * <p>
     * Bridges are skipped, they only forward traffic
     * to a relay and never appear as the exit address.
     * </p>
     *
     * @param json the relay list
     * @return the relay addresses
     */
    @NonNull
    public static List<String> parse(@NonNull String json) {
        List<String> entries = new ArrayList<>();
        for (JsonElement element : AntiVPN.GSON.fromJson(json, JsonArray.class)) {
            JsonObject relay = element.getAsJsonObject();
            JsonElement active = relay.get("active");
            JsonElement type = relay.get("type");
            if (active != null && !active.isJsonNull() && !active.getAsBoolean()) {
                continue;
            }
            if (type != null && !type.isJsonNull() && type.getAsString().equalsIgnoreCase("bridge")) {
                continue;
            }
            for (String key : new String[] { "ipv4_addr_in", "ipv6_addr_in" }) {
                JsonElement value = relay.get(key);
                if (value != null && !value.isJsonNull() && !value.getAsString().isBlank()) {
                    entries.add(value.getAsString());
                }
            }
        }
        return entries;
    }
}
