package me.braydon.antivpn.metrics;

import com.influxdb.client.InfluxDBClient;
import com.influxdb.client.InfluxDBClientFactory;
import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metrics.impl.DatabaseTracker;
import me.braydon.antivpn.metrics.impl.ProviderTracker;
import me.braydon.antivpn.metrics.impl.RequestTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @author Braydon
 */
@Service
public final class MetricService {
    private static final Logger log = LoggerFactory.getLogger("Metrics");
    
    /**
     * The url to connect to.
     */
    @Value("${influxdb.url}")
    private String url;
    
    /**
     * The authentication token
     * to use when connecting.
     */
    @Value("${influxdb.token}")
    private String token;
    
    /**
     * The organization to connect to.
     */
    @Value("${influxdb.org}")
    private String org;
    
    /**
     * The bucket to store data in.
     */
    @Value("${influxdb.bucket}")
    private String bucket;
    
    /**
     * The registered trackers.
     */
    private final Set<MetricTracker> trackers = Collections.synchronizedSet(new HashSet<>());
    
    /**
     * The unix time of the last metric log.
     */
    private long lastLog;
    
    @PostConstruct
    public void initialize() {
        // Registering tracks
        trackers.add(new ProviderTracker()); // Provider tracking
        trackers.add(new DatabaseTracker()); // Database tracking
        trackers.add(new RequestTracker()); // Request tracking
        
        // Creating a new thread to tick trackers at their respective intervals
        new Thread(() -> {
            while (true) {
                List<Point> points = new ArrayList<>(); // The points to write
                for (MetricTracker tracker : trackers) {
                    // Can't track just yet
                    if ((System.currentTimeMillis() - tracker.getLastExecution()) < tracker.getInterval()) {
                        continue;
                    }
                    try {
                        tracker.track(points); // The points to write
                        tracker.setLastExecution(System.currentTimeMillis()); // Just executed the tracker
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
                if (!points.isEmpty()) { // We have things to write
                    points.add(Point.measurement("pointsPerSecond")
                                   .addField("value", points.size())
                                   .time(Instant.now().toEpochMilli(), WritePrecision.MS)); // PPS metric
                    // Writing to Influx
                    try (InfluxDBClient client = InfluxDBClientFactory.create(url, token.toCharArray(), org, bucket)) {
                        client.getWriteApiBlocking().writePoints(points);
                    }
                    if ((System.currentTimeMillis() - lastLog) >= TimeUnit.SECONDS.toMillis(10L)) { // Should we log?
                        lastLog = System.currentTimeMillis(); // Last logged now
                        log.info("Wrote {} points to InfluxDB", points.size()); // Log the amount of points written
                    }
                    points.clear(); // Clear the points from memory after we're done submitting them
                }
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }
        }, "Metric Tracker").start();
    }
    
    /**
     * Get the tracker by the given class.
     *
     * @param clazz the class
     * @param <T>   the type of tracker
     * @return the tracker
     * @throws IllegalArgumentException if no tracker is found
     * @see MetricTracker for tracker
     */
    public <T extends MetricTracker> T getTracker(@NonNull Class<T> clazz) {
        for (MetricTracker tracker : trackers) {
            if (!tracker.getClass().equals(clazz)) { // Not the one we're looking for
                continue;
            }
            return clazz.cast(tracker); // Cast the tracker to the given class
        }
        throw new IllegalArgumentException("No tracker found for " + clazz.getSimpleName()); // No tracker found
    }
}
