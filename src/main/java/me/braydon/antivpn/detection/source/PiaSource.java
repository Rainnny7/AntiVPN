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
import java.util.Map;

/**
 * Private Internet Access servers, from the server
 * list the PIA clients use to pick a server.
 *
 * @author Braydon
 */
@Component
public final class PiaSource extends DetectionSource {
    private static final String ENDPOINT = "https://serverlist.piaservers.net/vpninfo/servers/v6";
    
    public PiaSource() {
        super("pia", "Private Internet Access", Category.VPN, Confidence.CONFIRMED, Duration.ofHours(1L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        return parse(WebRequest.builder().url(ENDPOINT).build().sendAsString());
    }
    
    /**
     * Parse the server list, taking the IP of every
     * server in every protocol group of every region.
     * <p>
     * The body is the JSON on the first line, followed by a signature.
     * </p>
     *
     * @param body the server list
     * @return the server addresses
     */
    @NonNull
    public static List<String> parse(@NonNull String body) {
        String json = body.split("\\R", 2)[0];
        List<String> entries = new ArrayList<>();
        JsonObject root = AntiVPN.GSON.fromJson(json, JsonObject.class);
        for (JsonElement regionElement : root.getAsJsonArray("regions")) {
            JsonObject servers = regionElement.getAsJsonObject().getAsJsonObject("servers");
            if (servers == null) {
                continue;
            }
            for (Map.Entry<String, JsonElement> group : servers.entrySet()) {
                if (!group.getValue().isJsonArray()) {
                    continue;
                }
                JsonArray groupServers = group.getValue().getAsJsonArray();
                for (JsonElement server : groupServers) {
                    JsonElement ip = server.getAsJsonObject().get("ip");
                    if (ip != null && !ip.isJsonNull()) {
                        entries.add(ip.getAsString());
                    }
                }
            }
        }
        return entries;
    }
}
