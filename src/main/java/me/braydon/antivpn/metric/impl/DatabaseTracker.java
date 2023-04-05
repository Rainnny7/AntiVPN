package me.braydon.antivpn.metric.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metric.MetricTracker;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

/**
 * @author Braydon
 */
public final class DatabaseTracker extends MetricTracker {
    private final ConcurrentHashMap<DatabaseType, CopyOnWriteArrayList<Long>> responseTimes = new ConcurrentHashMap<>(); // Response times
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
        for (DatabaseType databaseType : DatabaseType.values()) {
            List<Long> responseTimes = this.responseTimes.get(databaseType);
            int responseCount = 0;
            long totalResponseTime = 0L;
            if (responseTimes != null) { // We have response times for this database type
                responseCount = responseTimes.size();
                for (long responseTime : responseTimes) { // Iterate through the response times for this database
                    totalResponseTime += responseTime;
                }
            }
            long averageResponseTime = responseCount > 0L ? totalResponseTime / responseCount : 0L;
            chain.add(Point.measurement("databaseResponseTimes")
                          .addTag("type", databaseType.name())
                          .addField("value", averageResponseTime));
        }
        responseTimes.clear(); // Clear the response times
        
        // Cache stats
        BiFunction<String, Integer, Point> getCachePoint = (tag, value) -> Point.measurement("cache")
                                                                               .addTag("type", tag)
                                                                               .addField("value", value)
                                                                               .time(Instant.now().toEpochMilli(), WritePrecision.MS);
        chain.add(getCachePoint.apply("HIT", cacheHits));
        chain.add(getCachePoint.apply("MISS", cacheMisses));
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
        responseTimes.computeIfAbsent(type, databaseType -> new CopyOnWriteArrayList<>()).add(time);
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
