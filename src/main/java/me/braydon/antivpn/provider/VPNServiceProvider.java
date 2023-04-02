package me.braydon.antivpn.provider;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import me.braydon.antivpn.AntiVPN;
import org.apache.logging.log4j.Level;
import org.apache.logging.slf4j.SLF4JLogger;
import org.springframework.data.redis.connection.DefaultStringRedisConnection;
import org.springframework.data.redis.connection.StringRedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

/**
 * Represents a VPN provider.
 *
 * @author Braydon
 */
@Getter
public abstract class VPNServiceProvider {
    /**
     * The registered {@link VPNServiceProvider}'s.
     */
    @Getter private static final Set<VPNServiceProvider> registry = Collections.synchronizedSet(new HashSet<>());
    
    /**
     * The name of this provider.
     */
    @NonNull private final String name;
    
    /**
     * The expiration time for IPs
     * belonging to this provider.
     */
    private final long ipExpiration;
    
    /**
     * The logger to use for this provider.
     *
     * @see SLF4JLogger for logger
     */
    @NonNull private final SLF4JLogger logger;
    
    /**
     * The scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    @NonNull private final Set<ScrapeTask> scrapeTasks = Collections.synchronizedSet(new LinkedHashSet<>());
    
    /**
     * The scraped IPs.
     * <p>
     * This just acts as a cache so we don't flood the database
     * with a query each additional IP added, and instead we can
     * just add them in bulk.
     * </p>
     */
    @NonNull private final Set<String> scrapedIps = Collections.synchronizedSet(new HashSet<>());
    
    public VPNServiceProvider(@NonNull String name, long ipExpiration) {
        this.name = name;
        this.ipExpiration = ipExpiration;
        logger = (SLF4JLogger) org.apache.logging.log4j.LogManager.getLogger(name); // Setup the logger
        registry.add(this); // Register this provider
    }
    
    /**
     * Add the given scrape task.
     *
     * @param task the scrape task
     * @see ScrapeTask for scrape task
     */
    protected final void addScrapeTask(@NonNull ScrapeTask task) {
        scrapeTasks.add(task);
    }
    
    /**
     * Add the given IP to this provider.
     *
     * @param ip the ip to add
     */
    public final void addIp(@NonNull String ip) {
        scrapedIps.add(ip); // Add the IP
    }
    
    /**
     * Check if this provider has the given IP.
     *
     * @param jedisFactory the jedis factory instance
     * @param ip           the ip to check
     * @return true if it does, otherwise false
     * @see JedisConnectionFactory for jedis factory
     */
    public final boolean hasIp(@NonNull JedisConnectionFactory jedisFactory, @NonNull String ip) {
        long before = System.currentTimeMillis();
        try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
            boolean exists = redis.exists(getRedisKey() + ":" + ip); // Does the IP exist for this provider?
            log("Checked if the IP {} exists in the database in {}ms", ip, System.currentTimeMillis() - before); // Log timings
            return exists;
        }
    }
    
    /**
     * Get the IPs that belong to this provider.
     *
     * @param jedisFactory the jedis factory instance
     * @return the ips
     * @see StringRedisConnection for jedis factory
     */
    @NonNull
    public final Set<String> getIps(@NonNull JedisConnectionFactory jedisFactory) {
        long before = System.currentTimeMillis();
        Set<String> ips = new HashSet<>();
        try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
            String redisKey = getRedisKey();
            for (String key : redis.keys(redisKey + ":*")) {
                ips.add(key.substring(redisKey.length() + 1));
            }
        }
        log("Retrieved {} IPs from the database in {}ms", ips.size(), System.currentTimeMillis() - before); // Log timings
        return ips;
    }
    
    /**
     * Run the scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    public final void scrape(@NonNull JedisConnectionFactory jedisFactory) {
        int totalScrapeTasks = scrapeTasks.size();
        AtomicInteger completed = new AtomicInteger();
        for (ScrapeTask scrapeTask : scrapeTasks) {
            if (!scrapeTask.canRun()) { // Can't run
                continue;
            }
            AntiVPN.THREAD_POOL.submit(() -> {
                try {
                    scrapeTask.run(); // Run the task
                    completed.addAndGet(1); // Completed a task
                } catch (Exception ex) {
                    log(Level.ERROR, "An error occurred while scraping the provider", ex);
                }
            });
        }
        // Wait for all scrape tasks to complete. This is done so
        // we can add the scraped IPs in bulk instead of adding them
        // one by one which would flood the database with queries
        while (completed.get() < totalScrapeTasks) {
            try {
                Thread.sleep(100L);
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }
        if (!scrapedIps.isEmpty()) { // Insert the scraped IPs into the database if we have any
            log("Adding {} scraped IPs to the database...", scrapedIps.size());
            
            String redisKey = getRedisKey() + ":"; // The redis key
            String now = String.valueOf(System.currentTimeMillis()); // The current timestamp
            try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
                redis.openPipeline(); // Open a pipeline
                for (String scrapedIp : scrapedIps) { // Add the IPs to the database
                    redis.set(redisKey + scrapedIp, now);
                }
                int inserted = redis.closePipeline().size(); // Close the pipeline which then returns the results
                
                // Log the IPs being added
                log("Successfully inserted {} IPs into the database", inserted);
            }
        }
    }
    
    /**
     * Log the given message to the terminal
     * using the {@link Level#INFO} level.
     *
     * @param message the message to log
     * @param params  the optional message params
     * @see Level for level
     */
    protected final void log(@NonNull String message, @NonNull Object... params) {
        log(Level.INFO, message, params);
    }
    
    /**
     * Log the given message to the terminal.
     *
     * @param level   the level to log at
     * @param message the message to log
     * @param params  the optional message params
     * @see Level for level
     */
    protected final void log(@NonNull Level level, @NonNull String message, @NonNull Object... params) {
        logger.log(level, message, params);
    }
    
    /**
     * Purge IPs in the database that have expired.
     *
     * @param jedisFactory the jedis factory instance
     * @see StringRedisConnection for jedis factory
     */
    public final void purgeExpiredIps(@NonNull JedisConnectionFactory jedisFactory) {
        try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
            //            long currentTime = System.currentTimeMillis();
            //            long cutoffTime = currentTime - ipExpiration;
            //            long removed = redis.zRemRangeByScore(getRedisKey(), 0, cutoffTime);
            //            if (removed > 0L) { // Did we remove anything?
            //                log("Purged expired IPs");
            //            }
        }
    }
    
    /**
     * Get the key to use when identifying
     * this provider in Redis.
     *
     * @return the key
     */
    @NonNull
    public final String getRedisKey() {
        return "providers." + getClass().getSimpleName();
    }
    
    /**
     * Represents a timed scrape task.
     */
    public static class TimedScrapeTask extends ScrapeTask {
        /**
         * The delay at which this task runs at.
         */
        private final long delay;
        
        /**
         * The unix time of the last run.
         */
        private long lastRun;
        
        public TimedScrapeTask(long delay, @NonNull Runnable task) {
            super(() -> true, task);
            this.delay = delay;
        }
        
        /**
         * Check if this task can be executed.
         *
         * @return true if you can run, otherwise false
         */
        @Override
        public boolean canRun() {
            return System.currentTimeMillis() - lastRun >= delay;
        }
        
        /**
         * Run this task.
         */
        @Override
        public void run() {
            super.run();
            lastRun = System.currentTimeMillis();
        }
    }
    
    /**
     * Represents a scrape task.
     */
    @RequiredArgsConstructor
    public static class ScrapeTask {
        /**
         * The supplier to use when checking
         * if this task can be executed.
         *
         * @see BooleanSupplier for supplier
         */
        @NonNull private final BooleanSupplier canRun;
        
        /**
         * The task to run.
         *
         * @see Runnable for task
         */
        @NonNull private final Runnable task;
        
        /**
         * Check if this task can be executed.
         *
         * @return true if you can run, otherwise false
         */
        public boolean canRun() {
            return canRun.getAsBoolean();
        }
        
        /**
         * Run this task.
         */
        public void run() {
            task.run(); // Run the task
        }
    }
}