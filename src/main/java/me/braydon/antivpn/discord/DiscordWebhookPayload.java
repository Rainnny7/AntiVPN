package me.braydon.antivpn.discord;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.detection.Detection;
import me.braydon.antivpn.model.AddressData;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the JSON body posted to a Discord webhook for a lookup.
 *
 * @author Braydon
 */
@UtilityClass
public final class DiscordWebhookPayload {
    private static final int COLOR_VPN = 0xE74C3C;
    private static final int COLOR_ABUSE = 0xE67E22;
    private static final int COLOR_HOSTING = 0xF1C40F;
    private static final int COLOR_RELAY = 0x3498DB;
    private static final int COLOR_ALLOWLISTED = 0x95A5A6;
    private static final int COLOR_CLEAN = 0x2ECC71;
    private static final int MAX_EMBED_FIELDS = 25;
    
    /**
     * Build the webhook JSON for a lookup result.
     *
     * @param username the webhook username, blank to use the webhook's default
     * @param data     the lookup result
     * @param metadata optional request metadata
     * @return the JSON body
     */
    @NonNull
    public static String lookup(String username, @NonNull AddressData data, Map<String, String> metadata) {
        Map<String, String> safeMetadata = metadata == null ? Map.of() : metadata;
        
        Map<String, Object> embed = new LinkedHashMap<>();
        embed.put("title", title(data));
        embed.put("description", description(data, safeMetadata));
        embed.put("color", color(data));
        embed.put("timestamp", Instant.now().toString());
        embed.put("fields", fields(data, safeMetadata));
        embed.put("footer", Map.of("text", "AntiVPN"));
        
        Map<String, Object> payload = new LinkedHashMap<>();
        if (username != null && !username.isBlank()) {
            payload.put("username", username.trim());
        }
        payload.put("allowed_mentions", Map.of("parse", List.of()));
        payload.put("embeds", List.of(embed));
        return AntiVPN.GSON.toJson(payload);
    }
    
    @NonNull
    static String title(@NonNull AddressData data) {
        if (data.isAllowlisted()) {
            return "Allowlisted";
        }
        if (data.isVpn()) {
            return data.getProvider() == null ? "VPN detected" : data.getProvider() + " detected";
        }
        if (data.isTor()) {
            return "Tor detected";
        }
        if (data.isAbuse()) {
            return "Abusive network";
        }
        if (data.isHosting()) {
            return "Hosting / datacenter";
        }
        if (data.isRelay()) {
            return "iCloud Private Relay";
        }
        return "Lookup";
    }
    
    @NonNull
    static String description(@NonNull AddressData data, @NonNull Map<String, String> metadata) {
        String player = metadata.get("player");
        if (player != null && !player.isBlank()) {
            return "**" + discord(player) + "** looked up from `" + data.getIp() + "`";
        }
        return "Looked up `" + data.getIp() + "`";
    }
    
    static int color(@NonNull AddressData data) {
        if (data.isAllowlisted()) {
            return COLOR_ALLOWLISTED;
        }
        if (data.isVpn() || data.isTor()) {
            return COLOR_VPN;
        }
        if (data.isAbuse()) {
            return COLOR_ABUSE;
        }
        if (data.isHosting()) {
            return COLOR_HOSTING;
        }
        if (data.isRelay()) {
            return COLOR_RELAY;
        }
        return COLOR_CLEAN;
    }
    
    @NonNull
    private static List<Map<String, Object>> fields(@NonNull AddressData data, @NonNull Map<String, String> metadata) {
        List<Map<String, Object>> fields = new ArrayList<>();
        fields.add(field("IP", "`" + data.getIp() + "`", true));
        fields.add(field("Risk", String.format(Locale.ROOT, "%.2f", data.getRisk()), true));
        if (data.getProvider() != null && !data.getProvider().isBlank()) {
            fields.add(field("Provider", discord(data.getProvider()), true));
        }
        fields.add(field("Flags", flags(data), true));
        if (data.getCached() != null) {
            fields.add(field("Cached", "yes", true));
        }
        if (!data.getDetections().isEmpty()) {
            fields.add(field("Detections", detections(data.getDetections()), false));
        }
        
        List<Map.Entry<String, String>> remaining = new ArrayList<>(metadata.entrySet());
        for (int i = 0; i < remaining.size(); i++) {
            int room = MAX_EMBED_FIELDS - fields.size();
            if (room <= 0) {
                break;
            }
            boolean lastSlot = room == 1 && i < remaining.size() - 1;
            if (lastSlot) {
                StringBuilder leftover = new StringBuilder();
                for (int j = i; j < remaining.size(); j++) {
                    Map.Entry<String, String> entry = remaining.get(j);
                    if (!leftover.isEmpty()) {
                        leftover.append('\n');
                    }
                    leftover.append(discord(entry.getKey())).append(": ").append(discord(entry.getValue()));
                }
                fields.add(field("Metadata", leftover.toString(), false));
                break;
            }
            Map.Entry<String, String> entry = remaining.get(i);
            fields.add(field(discord(entry.getKey()), discord(entry.getValue()), true));
        }
        return fields;
    }
    
    @NonNull
    private static String flags(@NonNull AddressData data) {
        List<String> flags = new ArrayList<>();
        if (data.isVpn()) {
            flags.add("VPN");
        }
        if (data.isTor()) {
            flags.add("Tor");
        }
        if (data.isRelay()) {
            flags.add("Relay");
        }
        if (data.isHosting()) {
            flags.add("Hosting");
        }
        if (data.isAbuse()) {
            flags.add("Abuse");
        }
        if (data.isAllowlisted()) {
            flags.add("Allowlisted");
        }
        if (!data.getBlacklists().isEmpty()) {
            flags.add("Blacklist");
        }
        return flags.isEmpty() ? "Clean" : String.join(", ", flags);
    }
    
    @NonNull
    private static String detections(@NonNull List<Detection> detections) {
        StringBuilder builder = new StringBuilder();
        for (Detection detection : detections) {
            if (!builder.isEmpty()) {
                builder.append('\n');
            }
            builder.append(discord(detection.name()))
                .append(" — ")
                .append(detection.confidence().name().toLowerCase(Locale.ROOT))
                .append(" (`")
                .append(detection.range())
                .append("`)");
        }
        return builder.toString();
    }
    
    @NonNull
    private static Map<String, Object> field(@NonNull String name, @NonNull String value, boolean inline) {
        Map<String, Object> field = new LinkedHashMap<>();
        field.put("name", truncate(name, 256));
        field.put("value", truncate(value, 1024));
        field.put("inline", inline);
        return field;
    }
    
    @NonNull
    private static String discord(@NonNull String value) {
        return value.replace("```", "`\u200b``");
    }
    
    @NonNull
    private static String truncate(@NonNull String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
