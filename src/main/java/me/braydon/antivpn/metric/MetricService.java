package me.braydon.antivpn.metric;

import com.influxdb.client.InfluxDBClient;
import com.influxdb.client.InfluxDBClientFactory;
import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.NonNull;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.detection.SourceState;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.metric.impl.ProviderTracker;
import me.braydon.antivpn.metric.impl.RequestTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
    @Value("${influxdb.url:}")
    private String url;
    
    /**
     * The authentication token
     * to use when connecting.
     */
    @Value("${influxdb.token:}")
    private String token;
    
    /**
     * The organization to connect to.
     */
    @Value("${influxdb.org:}")
    private String org;
    
    /**
     * The bucket to store data in.
     */
    @Value("${influxdb.bucket:}")
    private String bucket;
    
    /**
     * The registered trackers.
     */
    @NonNull private final Set<MetricTracker> trackers = Collections.synchronizedSet(new HashSet<>());
    
    /**
     * The InfluxDB client to use, null if metrics are disabled.
     *
     * @see InfluxDBClient for client
     */
    private InfluxDBClient client;
    
    /**
     * The thread writing metrics, null if metrics are disabled.
     */
    private Thread thread;
    
    /**
     * The unix time of the last metric log.
     */
    private long lastLog;
    
    public MetricService(@NonNull ObjectProvider<DetectionService> detectionService) {
        // Trackers are always registered so callers can submit metrics even when InfluxDB is disabled
        trackers.add(new ProviderTracker(() -> {
            Map<String, Integer> counts = new LinkedHashMap<>();
            DetectionService service = detectionService.getIfAvailable();
            if (service != null) {
                for (SourceState state : service.getStates()) {
                    counts.put(state.getSource().getName(), state.getIndex().size());
                }
            }
            return counts;
        }));
        trackers.add(new DatabaseTracker());
        trackers.add(new RequestTracker());
    }
    
    @PostConstruct
    public void initialize() {
        if (url == null || url.isBlank()) { // Don't enable metrics if the url is empty
            log.warn("InfluxDB URL is empty, metrics will not be written");
            return;
        }
        client = InfluxDBClientFactory.create(url, token.toCharArray(), org, bucket);
        
        // Creating a new thread to tick trackers at their respective intervals
        thread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    tick();
                } catch (Exception ex) {
                    log.error("Failed to write metrics", ex);
                }
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "Metric Tracker");
        thread.setDaemon(true);
        thread.start();
    }
    
    private void tick() {
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
                log.error("An error occurred while tracking metrics", ex);
            }
        }
        if (points.isEmpty()) { // Nothing to write
            return;
        }
        points.add(Point.measurement("pointsPerSecond")
                       .addField("value", points.size())
                       .time(Instant.now().toEpochMilli(), WritePrecision.MS)); // PPS metric
        
        // Tagging all points with the current environment
        for (Point point : points) {
            point.addTag("environment", AntiVPN.isDevelopment() ? "dev" : "prod");
        }
        
        // Writing to Influx
        long before = System.currentTimeMillis(); // Before we wrote to Influx
        client.getWriteApiBlocking().writePoints(points);
        long influxTimings = System.currentTimeMillis() - before;
        
        // Running metrics on metrics :>
        getTracker(DatabaseTracker.class).submitResponseTime(DatabaseTracker.DatabaseType.INFLUXDB, influxTimings);
        
        if ((System.currentTimeMillis() - lastLog) >= TimeUnit.SECONDS.toMillis(10L)) { // Should we log?
            lastLog = System.currentTimeMillis(); // Last logged now
            log.debug("Wrote {} point(s) to InfluxDB in {}ms", points.size(), influxTimings);
        }
    }
    
    @PreDestroy
    public void destroy() {
        if (thread != null) {
            thread.interrupt();
        }
        if (client != null) {
            client.close(); // Close the client
        }
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
        synchronized (trackers) {
            for (MetricTracker tracker : trackers) {
                if (tracker.getClass().equals(clazz)) {
                    return clazz.cast(tracker); // Cast the tracker to the given class
                }
            }
        }
        throw new IllegalArgumentException("No tracker found for " + clazz.getSimpleName()); // No tracker found
    }
}
