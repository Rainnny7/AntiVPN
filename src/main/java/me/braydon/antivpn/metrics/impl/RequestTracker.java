package me.braydon.antivpn.metrics.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metrics.MetricTracker;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * This tracker tracks the amount of requests that have
 * been received in the last {@link super#getInterval()} ()}
 *
 * @author Braydon
 */
public final class RequestTracker extends MetricTracker {
    private int currentRequests; // The currently cached requests
    
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
     * @return the points to write, empty for none
     * @see Point for point
     */
    @Override @NonNull
    public List<Point> track() {
        int requestsLastInterval = currentRequests; // The requests in the last interval
        currentRequests = 0; // Clear the current requests
        if (requestsLastInterval == 0) { // No data to write
            return Collections.emptyList();
        }
        return List.of(Point.measurement("requests")
                           .addField("value", requestsLastInterval)
                           .time(Instant.now().toEpochMilli(), WritePrecision.MS));
    }
    
    /**
     * Submit a request to this tracker.
     */
    public void submitRequest() {
        currentRequests++;
    }
}