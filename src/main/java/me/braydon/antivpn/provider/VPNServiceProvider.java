package me.braydon.antivpn.provider;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import me.braydon.antivpn.common.StringUtils;
import me.braydon.antivpn.metrics.MetricService;
import me.braydon.antivpn.metrics.impl.DatabaseTracker;
import org.apache.logging.log4j.Level;
import org.apache.logging.slf4j.SLF4JLogger;
import org.springframework.data.redis.connection.DefaultStringRedisConnection;
import org.springframework.data.redis.connection.RedisStringCommands;
import org.springframework.data.redis.connection.StringRedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.types.Expiration;

import java.util.*;
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
     * The metrics service instance to use.
     */
    @NonNull private final MetricService metrics;
    
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
    @NonNull private final Set<String> scrapedIps = Collections.synchronizedSet(new TreeSet<>());
    
    public VPNServiceProvider(@NonNull String name, long ipExpiration, @NonNull MetricService metrics) {
        this.name = name;
        this.ipExpiration = ipExpiration;
        logger = (SLF4JLogger) org.apache.logging.log4j.LogManager.getLogger(name); // Setup the logger
        this.metrics = metrics;
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
     * @param jedisFactory the jedis factory instance
     * @param ip           the ip to add
     * @see JedisConnectionFactory for jedis factory
     */
    public final void addIp(@NonNull JedisConnectionFactory jedisFactory, @NonNull String ip) {
        if (!hasIp(jedisFactory, ip)) {
            scrapedIps.add(ip); // Add the IP
        }
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
        boolean exists;
        if (scrapedIps.contains(ip)) { // Check the local cache first
            exists = true;
        } else {
            try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
                exists = redis.exists(getRedisKey() + ":" + ip); // Does the IP exist for this provider?
            }
        }
        metrics.getTracker(DatabaseTracker.class).submitResponseTime(
            DatabaseTracker.DatabaseType.REDIS, System.currentTimeMillis() - before); // Metrics
        return exists;
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
        String redisKey = getRedisKey() + ":";
        try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
            redis.keys(redisKey + "*")
                .parallelStream()
                .map(key -> key.substring(redisKey.length())) // Extract the IP address
                .forEach(ips::add); // Add the IP address to the set
        }
        metrics.getTracker(DatabaseTracker.class).submitResponseTime(
            DatabaseTracker.DatabaseType.REDIS, System.currentTimeMillis() - before); // Metrics
        log("Retrieved {} IPs from the database in {}ms",
            StringUtils.formatNumber(ips.size()),
            System.currentTimeMillis() - before
        ); // Log timings
        return ips;
    }
    
    /**
     * Run the scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    public final void scrape(@NonNull JedisConnectionFactory jedisFactory) {
        for (ScrapeTask scrapeTask : scrapeTasks) {
            if (!scrapeTask.canRun()) { // Can't run
                continue;
            }
            try {
                log("Running task {}...", scrapeTask.getName()); // Log that we're running the task
                scrapeTask.run(); // Run the task
                log("Completed task {}!", scrapeTask.getName()); // Log that we completed the task
            } catch (Exception ex) {
                log(Level.ERROR, "An error occurred while scraping the provider", ex);
            }
        }
        if (!scrapedIps.isEmpty()) { // Insert the scraped IPs into the database if we have any
            log("Adding {} scraped IPs to the database...", StringUtils.formatNumber(scrapedIps.size()));
            
            String redisKey = getRedisKey() + ":"; // The redis key
            String now = String.valueOf(System.currentTimeMillis()); // The current timestamp
            long before = System.currentTimeMillis();
            try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
                redis.openPipeline(); // Open a pipeline
                for (String scrapedIp : scrapedIps) { // Add the IPs to the database
                    redis.set(redisKey + scrapedIp, now, Expiration.persistent(), RedisStringCommands.SetOption.ifAbsent());
                }
                int inserted = redis.closePipeline().size(); // Close the pipeline which then returns the results
                
                // Log the IPs being added
                log("Successfully inserted {} IPs into the database, took {}ms",
                    StringUtils.formatNumber(inserted), System.currentTimeMillis() - before
                );
            }
            metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                DatabaseTracker.DatabaseType.REDIS, System.currentTimeMillis() - before); // Metrics
            scrapedIps.clear(); // Clear the scraped IPs after we've inserted them
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
        // TODO: purge expired IPs
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
     * Get the provider IP counts.
     *
     * @param jedisFactory the jedis factory instance
     * @return the provider IP counts
     * @see StringRedisConnection for jedis factory
     */
    @NonNull
    public static Map<String, Integer> getProviderIpCounts(@NonNull JedisConnectionFactory jedisFactory) {
        Map<String, Integer> mappedProviderIps = new HashMap<>();
        try (StringRedisConnection redis = new DefaultStringRedisConnection(jedisFactory.getConnection())) {
            redis.keys("providers.*") // Get all provider IP addresses
                .parallelStream()
                .forEach(key -> {
                    String[] split = key.split(":");
                    String provider = split[0].split("\\.")[1];// The provider name
                    mappedProviderIps.put(provider,
                        mappedProviderIps.getOrDefault(provider, 0) + 1); // Increment the provider IP count
                });
        }
        return mappedProviderIps;
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
        
        public TimedScrapeTask(@NonNull String name, long delay, @NonNull Runnable task) {
            super(name, () -> true, task);
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
         * The name of this task.
         */
        @NonNull @Getter private final String name;
        
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