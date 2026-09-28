package me.braydon.antivpn.discord;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.Detection;
import me.braydon.antivpn.model.AddressData;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DiscordWebhookPayloadTest {
    @Test
    void vpnLookupIncludesProviderFlagsAndMetadata() {
        AddressData data = new AddressData("89.35.28.131", 4, 1F, true, true, "NordVPN", false, false, true, false,
            false, Set.of(), List.of(new Detection("nordvpn", "NordVPN", Category.VPN, Confidence.CONFIRMED, "89.35.28.131")),
            null, null);
        
        JsonObject payload = AntiVPN.GSON.fromJson(DiscordWebhookPayload.lookup("AntiVPN", data, Map.of("player", "Steve")), JsonObject.class);
        JsonObject embed = payload.getAsJsonArray("embeds").get(0).getAsJsonObject();
        
        assertThat(payload.get("username").getAsString()).isEqualTo("AntiVPN");
        assertThat(payload.getAsJsonObject("allowed_mentions").getAsJsonArray("parse")).isEmpty();
        assertThat(embed.get("title").getAsString()).isEqualTo("NordVPN detected");
        assertThat(embed.get("description").getAsString()).isEqualTo("**Steve** looked up from `89.35.28.131`");
        assertThat(embed.get("color").getAsInt()).isEqualTo(0xE74C3C);
        assertThat(field(embed, "IP")).isEqualTo("`89.35.28.131`");
        assertThat(field(embed, "Risk")).isEqualTo("1.00");
        assertThat(field(embed, "Provider")).isEqualTo("NordVPN");
        assertThat(field(embed, "Flags")).isEqualTo("VPN, Hosting");
        assertThat(field(embed, "Detections")).contains("NordVPN — confirmed");
        assertThat(field(embed, "player")).isEqualTo("Steve");
    }
    
    @Test
    void cleanLookupHasANeutralTitle() {
        AddressData data = new AddressData("1.128.0.1", 4, 0F, false, false, null, false, false, false, false,
            false, Set.of(), List.of(), null, null);
        
        JsonObject embed = AntiVPN.GSON.fromJson(DiscordWebhookPayload.lookup(null, data, Map.of()), JsonObject.class)
                                 .getAsJsonArray("embeds").get(0).getAsJsonObject();
        
        assertThat(embed.get("title").getAsString()).isEqualTo("Lookup");
        assertThat(embed.get("description").getAsString()).isEqualTo("Looked up `1.128.0.1`");
        assertThat(embed.get("color").getAsInt()).isEqualTo(0x2ECC71);
        assertThat(field(embed, "Flags")).isEqualTo("Clean");
    }
    
    @Test
    void leftoverMetadataFitsInTheLastField() {
        AddressData data = new AddressData("1.128.0.1", 4, 0F, false, false, null, false, false, false, false,
            false, Set.of(), List.of(), null, null);
        Map<String, String> metadata = new LinkedHashMap<>();
        for (int i = 0; i < 30; i++) {
            metadata.put("k" + i, "v" + i);
        }
        
        JsonArray fields = AntiVPN.GSON.fromJson(DiscordWebhookPayload.lookup("AntiVPN", data, metadata), JsonObject.class)
                                 .getAsJsonArray("embeds").get(0).getAsJsonObject().getAsJsonArray("fields");
        
        assertThat(fields.size()).isLessThanOrEqualTo(25);
        JsonObject last = fields.get(fields.size() - 1).getAsJsonObject();
        assertThat(last.get("name").getAsString()).isEqualTo("Metadata");
        assertThat(last.get("value").getAsString()).contains("k29: v29");
    }
    
    private static String field(JsonObject embed, String name) {
        for (var element : embed.getAsJsonArray("fields")) {
            JsonObject field = element.getAsJsonObject();
            if (name.equals(field.get("name").getAsString())) {
                return field.get("value").getAsString();
            }
        }
        throw new AssertionError("Missing field: " + name);
    }
}
