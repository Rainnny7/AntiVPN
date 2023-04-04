package me.braydon.antivpn.metrics.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metrics.MetricTracker;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

/**
 * @author Braydon
 */
public final class DatabaseTracker extends MetricTracker {
    private final Map<DatabaseType, List<Long>> responseTimes = new HashMap<>(); // Response times
    private int cacheHits, cacheMisses; // Cache stats
    
    public DatabaseTracker() {
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
     * @see Point for point
     */
    @Override
    public void track(@NonNull List<Point> chain) {
        // Response times
        for (Map.Entry<DatabaseType, List<Long>> entry : responseTimes.entrySet()) { // Iterate through the response times
            List<Long> responseTimes = new ArrayList<>(entry.getValue());
            long totalResponseTime = 0L;
            for (long responseTime : responseTimes) { // Iterate through the response times for this database
                totalResponseTime += responseTime;
            }
            chain.add(Point.measurement("databaseResponseTimes")
                          .addTag("type", entry.getKey().name())
                          .addField("value", totalResponseTime / responseTimes.size()));
        }
        responseTimes.clear(); // Clear the response times
        
        // Cache stats
        BiFunction<String, Integer, Point> getCachePoint = (tag, value) -> Point.measurement("cache")
                                                                               .addTag("type", tag)
                                                                               .addField("value", value)
                                                                               .time(Instant.now().toEpochMilli(), WritePrecision.MS);
        if (cacheHits > 0) { // If there are any cache hits
            chain.add(getCachePoint.apply("HIT", cacheHits));
        }
        if (cacheMisses > 0) { // If there are any cache misses
            chain.add(getCachePoint.apply("MISS", cacheMisses));
        }
        cacheHits = cacheMisses = 0; // Clear cache stats
    }
    
    /**
     * Update the response time for a database.
     *
     * @param type the type of database
     * @param time the response time
     * @see DatabaseType for database
     */
    public void submitResponseTime(@NonNull DatabaseType type, long time) {
        responseTimes.computeIfAbsent(type, databaseType -> new ArrayList<>()).add(time);
    }
    
    /**
     * Submit a cache hit to this tracker.
     */
    public void submitCacheHit() {
        cacheHits++;
    }
    
    /**
     * Submit a cache miss to this tracker.
     */
    public void submitCacheMiss() {
        cacheMisses++;
    }
    
    /**
     * The databases to keep track of.
     */
    public enum DatabaseType {
        MONGODB,
        REDIS
    }
}
