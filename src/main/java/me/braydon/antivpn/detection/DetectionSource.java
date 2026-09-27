package me.braydon.antivpn.detection;

import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.time.Duration;
import java.util.List;

/**
 * An upstream list of IP addresses or CIDR blocks.
 * <p>
 * Implementations are Spring beans and are refreshed
 * on a schedule by the {@link DetectionService}.
 * </p>
 *
 * @author Braydon
 */
@Getter @ToString(onlyExplicitlyIncluded = true)
public abstract class DetectionSource {
    /**
     * The unique id of this source, used for snapshots and config.
     */
    @ToString.Include @NonNull private final String id;
    
    /**
     * The display name of this source.
     */
    @NonNull private final String name;
    
    /**
     * What a match from this source means.
     */
    @NonNull private final Category category;
    
    /**
     * How certain a match from this source is.
     */
    @NonNull private final Confidence confidence;
    
    /**
     * How often this source is refreshed.
     */
    @NonNull private final Duration refreshInterval;
    
    protected DetectionSource(@NonNull String id, @NonNull String name, @NonNull Category category,
                              @NonNull Confidence confidence, @NonNull Duration refreshInterval) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.confidence = confidence;
        this.refreshInterval = refreshInterval;
    }
    
    /**
     * Fetch the current entries (CIDR blocks or single addresses) from upstream.
     *
     * @return the entries
     * @throws Exception if the fetch fails
     */
    @NonNull
    public abstract List<String> fetch() throws Exception;
    
    /**
     * How long entries are kept after they were last seen.
     * <p>
     * By default a successful refresh replaces every entry. Sources
     * that only see part of their data per fetch (e.g. DNS round-robin)
     * return a retention so entries accumulate across refreshes.
     * </p>
     *
     * @return the retention, or null to replace entries on every refresh
     */
    public Duration getRetention() {
        return null;
    }
}
