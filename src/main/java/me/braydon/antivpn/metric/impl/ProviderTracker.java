package me.braydon.antivpn.metric.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metric.MetricTracker;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Tracks the amount of blocks loaded for each detection source.
 *
 * @author Braydon
 */
public final class ProviderTracker extends MetricTracker {
    /**
     * Supplies the block count of each source, keyed by source name.
     */
    @NonNull private final Supplier<Map<String, Integer>> counts;
    
    public ProviderTracker(@NonNull Supplier<Map<String, Integer>> counts) {
        super(TimeUnit.SECONDS.toMillis(10L));
        this.counts = counts;
    }
    
    /**
     * Execute this tracker.
     * <p>
     * This method will only
     * be invoked at the given
     * interval for this tracker.
     * </p>
     *
     * @param chain the chain of points to attach to
     * @see Point for point
     */
    @Override
    public void track(@NonNull List<Point> chain) {
        for (Map.Entry<String, Integer> entry : counts.get().entrySet()) {
            chain.add(Point.measurement("providerIps")
                          .addTag("provider", entry.getKey())
                          .addField("value", entry.getValue())
                          .time(Instant.now().toEpochMilli(), WritePrecision.MS));
        }
    }
}
