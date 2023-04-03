package me.braydon.antivpn.metrics;

import com.influxdb.client.write.Point;
import lombok.*;

import java.util.List;

/**
 * Represents a tracker for metrics.
 *
 * @author Braydon
 */
@RequiredArgsConstructor @Setter(AccessLevel.PROTECTED) @Getter(AccessLevel.PROTECTED) @ToString
public abstract class MetricTracker {
    /**
     * The interval at which this
     * tracker should be executed at.
     */
    private final long interval;
    
    /**
     * The unix time of when this
     * tracker was last executed.
     */
    private long lastExecution;
    
    /**
     * Execute this tracker.
     * <p>
     * This method will only
     * be invoked at the given
     * interval for this tracker.
     * </p>
     *
     * @return the points to write, empty for none
     * @see Point for point
     */
    @NonNull
    public abstract List<Point> track();
    
    /**
     * Get the name of this metric tracker.
     *
     * @return the name
     */
    @NonNull
    public final String getName() {
        return getClass().getSimpleName();
    }
}