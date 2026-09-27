package me.braydon.antivpn.metric.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metric.MetricTracker;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

/**
 * This tracker tracks the amount of requests that have
 * been received in the last {@link MetricTracker#getInterval()}
 *
 * @author Braydon
 */
public final class RequestTracker extends MetricTracker {
    private final AtomicInteger currentRequests = new AtomicInteger(); // The currently cached requests
    private final AtomicInteger lookups = new AtomicInteger(); // The amount of lookup requests
    
    public RequestTracker() {
        super(TimeUnit.SECONDS.toMillis(5L));
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
        BiFunction<String, Integer, Point> getPoint = (tag, value) -> Point.measurement("requests")
                                                                          .addTag("type", tag)
                                                                          .addField("value", value)
                                                                          .time(Instant.now().toEpochMilli(), WritePrecision.MS);
        chain.add(getPoint.apply("NORMAL", currentRequests.getAndSet(0))); // All requests
        chain.add(getPoint.apply("LOOKUPS", lookups.getAndSet(0))); // Lookup requests
    }
    
    /**
     * Submit a request to this tracker.
     */
    public void submitRequest() {
        currentRequests.incrementAndGet();
    }
    
    /**
     * Submit a lookup request to this tracker.
     */
    public void submitLookup() {
        lookups.incrementAndGet();
    }
}
