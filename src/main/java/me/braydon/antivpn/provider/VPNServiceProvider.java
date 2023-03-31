package me.braydon.antivpn.provider;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.Level;
import org.apache.logging.slf4j.SLF4JLogger;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BooleanSupplier;

/**
 * Represents a VPN provider.
 *
 * @author Braydon
 */
@Getter
public abstract class VPNServiceProvider {
    /**
     * The thread pool to use for scraping of providers.
     *
     * @see ExecutorService for thread pool
     */
    public static final ExecutorService THREAD_POOL = Executors.newCachedThreadPool();
    
    /**
     * The registered {@link VPNServiceProvider}'s.
     */
    @Getter private static final Set<VPNServiceProvider> registry = new HashSet<>();
    
    /**
     * The name of this provider.
     */
    @NonNull private final String name;
    
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
    @NonNull private final LinkedHashSet<ScrapeTask> scrapeTasks = new LinkedHashSet<>();
    
    /**
     * The IPs that belong to this provider.
     */
    @NonNull private final Set<String> ips = Collections.synchronizedSet(new HashSet<>());
    
    public VPNServiceProvider(@NonNull String name) {
        this.name = name;
        logger = (SLF4JLogger) org.apache.logging.log4j.LogManager.getLogger(name); // Setup the logger
        registry.add(this); // Register the provider
    }
    
    /**
     * Add the given scrape task.
     *
     * @param task the scrape task
     * @see ScrapeTask for scrape task
     */
    protected void addScrapeTask(@NonNull ScrapeTask task) {
        scrapeTasks.add(task);
    }
    
    /**
     * Add the given IP to this provider.
     *
     * @param ip the ip to add
     */
    public void addIp(@NonNull String ip, @NonNull String reason) {
        if (ips.add(ip)) {
            log("Added IP ({}): {}", reason, ip); // Log the IP being added
        }
    }
    
    /**
     * Check if this provider has the given IP.
     *
     * @param ip the ip to check
     * @return true if it does, otherwise false
     */
    public boolean hasIp(@NonNull String ip) {
        return ips.contains(ip);
    }
    
    /**
     * Run the scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    public final void scrape() {
        for (ScrapeTask scrapeTask : scrapeTasks) {
            if (!scrapeTask.canRun()) { // Can't run
                continue;
            }
            scrapeTask.run(); // Run the task
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
    protected void log(@NonNull String message, @NonNull Object... params) {
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
    protected void log(@NonNull Level level, @NonNull String message, @NonNull Object... params) {
        logger.log(level, message, params);
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