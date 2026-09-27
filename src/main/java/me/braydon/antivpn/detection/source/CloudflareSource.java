package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Cloudflare's CDN and proxy ranges.
 * <p>
 * These are servers, not VPN exits. Cloudflare WARP
 * egress addresses are not part of these ranges.
 * </p>
 *
 * @author Braydon
 */
@Component
public final class CloudflareSource extends PlainListSource {
    public static final String ID = "cloudflare";
    
    public CloudflareSource() {
        super(ID, "Cloudflare", Category.HOSTING, Confidence.CONFIRMED, Duration.ofHours(24L),
            "https://www.cloudflare.com/ips-v4",
            "https://www.cloudflare.com/ips-v6"
        );
    }
}
