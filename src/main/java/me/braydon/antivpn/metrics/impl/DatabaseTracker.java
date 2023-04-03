package me.braydon.antivpn.metrics.impl;

import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metrics.MetricTracker;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author Braydon
 */
public final class DatabaseTracker extends MetricTracker {
    private final Map<DatabaseType, List<Long>> responseTimes = new HashMap<>();
    
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
     * @return the points to write, empty for none
     * @see Point for point
     */
    @Override @NonNull
    public List<Point> track() {
        List<Point> points = new ArrayList<>();
        for (Map.Entry<DatabaseType, List<Long>> entry : responseTimes.entrySet()) { // Iterate through the response times
            List<Long> responseTimes = new ArrayList<>(entry.getValue());
            long totalResponseTime = 0L;
            for (long responseTime : responseTimes) { // Iterate through the response times for this database
                totalResponseTime += responseTime;
            }
            points.add(Point.measurement("databaseResponseTimes")
                           .addTag("type", entry.getKey().name())
                           .addField("value", totalResponseTime / responseTimes.size()));
        }
        responseTimes.clear(); // Clear the response times
        return points;
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
     * The databases to keep track of.
     */
    public enum DatabaseType {
        MONGODB,
        REDIS
    }
}
