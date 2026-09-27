package me.braydon.antivpn.detection.source;

import lombok.NonNull;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.DetectionSource;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * iCloud Private Relay egress ranges, published by Apple.
 * <p>
 * Private Relay is used by ordinary iPhone, iPad and Mac users,
 * and its egress ranges live inside Akamai, Cloudflare and Fastly.
 * Matching here suppresses the hosting matches for those networks.
 * </p>
 *
 * @author Braydon
 */
@Component
public final class ICloudPrivateRelaySource extends DetectionSource {
    private static final String ENDPOINT = "https://mask-api.icloud.com/egress-ip-ranges.csv";
    
    public ICloudPrivateRelaySource() {
        super("icloud-private-relay", "iCloud Private Relay", Category.RELAY, Confidence.CONFIRMED, Duration.ofHours(24L));
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        return parse(WebRequest.builder().url(ENDPOINT).timeout(Duration.ofMinutes(2L)).build().sendAsString());
    }
    
    /**
     * Parse the egress CSV ({@code prefix,country,region,city,}).
     *
     * @param csv the csv
     * @return the egress ranges
     */
    @NonNull
    public static List<String> parse(@NonNull String csv) {
        List<String> entries = new ArrayList<>();
        for (String line : csv.split("\\R")) {
            int comma = line.indexOf(',');
            String prefix = (comma < 0 ? line : line.substring(0, comma)).trim();
            if (!prefix.isEmpty()) {
                entries.add(prefix);
            }
        }
        return entries;
    }
}
