package me.braydon.antivpn.detection;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for VPN detection, bound from {@code detection.*}.
 *
 * @author Braydon
 */
@ConfigurationProperties(prefix = "detection")
@Getter @Setter
public class DetectionProperties {
    /**
     * Whether sources are refreshed on a schedule.
     */
    private boolean schedulingEnabled = true;
    
    /**
     * Where the last good copy of each source is stored.
     */
    private Path snapshotDirectory = Path.of("data", "sources");
    
    /**
     * Ids of sources that should not be loaded.
     */
    private List<String> disabledSources = new ArrayList<>();
    
    /**
     * CIDR blocks of reverse proxies whose X-Forwarded-For header is trusted.
     */
    private List<String> trustedProxies = new ArrayList<>();
    
    /**
     * Whether to trust CF-Connecting-IP from requests that come from Cloudflare's ranges.
     */
    private boolean trustCloudflare = false;
    
    /**
     * A source is stale (and ignored) once its data is this many refresh intervals old.
     */
    private double staleAfterMultiplier = 3D;
    
    /**
     * The minimum age before a source is considered stale.
     */
    private Duration minStaleAfter = Duration.ofHours(24L);
    
    /**
     * A refresh is rejected if it has fewer entries than this fraction of the previous refresh.
     */
    private double minRetainedRatio = 0.5D;
    
    /**
     * A refresh is rejected if more than this fraction of its entries are
     * unsafe (too broad, or overlapping private/reserved space).
     */
    private double maxUnsafeRatio = 0.01D;
    
    /**
     * Extra ASNs to treat as hosting networks, on top of the bundled list.
     */
    private List<Long> extraHostingAsns = new ArrayList<>();
    
    /**
     * The risk weights of each signal.
     */
    private Weights weights = new Weights();
    
    @Getter @Setter
    public static class Weights {
        private float vpnConfirmed = 1F;
        private float vpnLikely = 0.75F;
        private float tor = 1F;
        private float abuse = 0.9F;
        private float hosting = 0.5F;
        private float relay = 0.1F;
        private float asnBlacklist = 0.5F;
        private float countryBlacklist = 0.4F;
    }
}
