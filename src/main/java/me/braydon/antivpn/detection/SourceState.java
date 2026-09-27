package me.braydon.antivpn.detection;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import me.braydon.antivpn.common.IpRangeIndex;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * The current data and health of a {@link DetectionSource}.
 *
 * @author Braydon
 */
@Getter @Setter
public final class SourceState {
    @NonNull private final DetectionSource source;
    
    /**
     * The current entries of the source.
     */
    @NonNull private volatile IpRangeIndex index = IpRangeIndex.empty();
    
    /**
     * When each entry was last seen, only kept for
     * sources with a {@link DetectionSource#getRetention()}.
     */
    @NonNull private volatile Map<String, Instant> lastSeen = Collections.emptyMap();
    
    /**
     * When the source was last successfully refreshed, null if never.
     */
    private volatile Instant updatedAt;
    
    /**
     * The amount of entries accepted from the last successful fetch.
     */
    private volatile int lastFetchCount;
    
    /**
     * When a refresh was last attempted.
     */
    private volatile Instant lastAttemptAt;
    
    /**
     * Why the last refresh failed or was rejected, null if it succeeded.
     */
    private volatile String lastError;
    
    SourceState(@NonNull DetectionSource source) {
        this.source = source;
    }
}
