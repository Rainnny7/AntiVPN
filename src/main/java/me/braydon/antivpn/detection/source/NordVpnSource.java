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
 * NordVPN servers, from NordVPN's public server API.
 *
 * @author Braydon
 */
@Component
public final class NordVpnSource extends DetectionSource {
    private static final String ENDPOINT = "https://api.nordvpn.com/v1/servers?limit=0"
                                           + "&fields%5Bservers.station%5D&fields%5Bservers.ipv6_station%5D";
    
    public NordVpnSource() {
        super("nordvpn", "NordVPN", Category.VPN, Confidence.CONFIRMED, Duration.ofHours(6L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        return parse(WebRequest.builder().url(ENDPOINT).timeout(Duration.ofSeconds(60L)).build().sendAsString());
    }
    
    /**
     * Parse the server list, taking the
     * {@code station} and {@code ipv6_station} of each server.
     *
     * @param json the server list
     * @return the server addresses
     */
    @NonNull
    public static List<String> parse(@NonNull String json) {
        List<String> entries = new ArrayList<>();
        for (JsonElement element : AntiVPN.GSON.fromJson(json, JsonArray.class)) {
            JsonObject server = element.getAsJsonObject();
            for (String key : new String[] { "station", "ipv6_station" }) {
                JsonElement value = server.get(key);
                if (value != null && !value.isJsonNull() && !value.getAsString().isBlank()) {
                    entries.add(value.getAsString());
                }
            }
        }
        return entries;
    }
}
