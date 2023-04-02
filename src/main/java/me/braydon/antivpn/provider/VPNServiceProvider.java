package me.braydon.antivpn.provider;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import me.braydon.antivpn.AntiVPN;
import org.apache.logging.log4j.Level;
import org.apache.logging.slf4j.SLF4JLogger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.BooleanSupplier;

/**
 * Represents a VPN provider.
 *
 * @author Braydon
 */
@Getter
public abstract class VPNServiceProvider {
    private static int THREAD_COUNT; // The thread count to keep track of threads
    
    /**
     * The thread pool to use for scraping of providers.
     *
     * @see ExecutorService for thread pool
     */
    public static final ExecutorService THREAD_POOL = Executors.newFixedThreadPool(12, task -> {
        return new Thread(task, "AntiVPN #" + (THREAD_COUNT++)); // Create a new thread
    }));
    
    /**
     * The registered {@link VPNServiceProvider}'s.
     */
    @Getter private static final Set<VPNServiceProvider> registry = new HashSet<>();
    
    /**
     * The name of this provider.
     */
    @NonNull private final String name;
    
    /**
     * The millis it takes for an IP address to expire.
     */
    private final long ipExpiration;
    
    /**
     * The logger to use for this provider.
     *
     * @see SLF4JLogger for logger
     */
    @NonNull private final SLF4JLogger logger;
    
    /**
     * The file where data for this provider is stored.
     */
    @NonNull private final File storageFile;
    
    /**
     * The scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    @NonNull private final LinkedHashSet<ScrapeTask> scrapeTasks = new LinkedHashSet<>();
    
    /**
     * The IPs that belong to this provider.
     */
    @NonNull private final Map<String, Long> ips = Collections.synchronizedMap(new HashMap<>());
    
    /**
     * Whether this provider is
     * dirty and needs to be saved.
     */
    private boolean dirty;
    
    public VPNServiceProvider(@NonNull String name, long ipExpiration) {
        this.name = name;
        this.ipExpiration = ipExpiration;
        logger = (SLF4JLogger) org.apache.logging.log4j.LogManager.getLogger(name); // Setup the logger
        
        // Handling storage
        storageFile = new File("providers", getClass().getSimpleName() + ".json"); // The storage file
        if (storageFile.exists()) { // Load the storage file if it exists
            try (FileReader fileReader = new FileReader(storageFile)) {
                JsonObject jsonObject = AntiVPN.GSON.fromJson(fileReader, JsonObject.class);
                
                // Loading IPs
                JsonObject ipsJsonObject = jsonObject.getAsJsonObject("ips");
                for (Map.Entry<String, JsonElement> entry : ipsJsonObject.entrySet()) {
                    ips.put(entry.getKey(), entry.getValue().getAsLong());
                }
                log("Loaded {} IPs", ips.size()); // Log the loaded IPs
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        // Register this provider
        registry.add(this);
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
    public final void addIp(@NonNull String ip, @NonNull String reason) {
        boolean previouslyContained = ips.containsKey(ip); // Whether we stored the IP previously
        ips.put(ip, System.currentTimeMillis());
        if (!previouslyContained) { // Log adding the IP
            dirty = true; // Mark as dirty
            log("Added IP ({}): {}", reason, ip); // Log the IP being added
        }
    }
    
    /**
     * Check if this provider has the given IP.
     *
     * @param ip the ip to check
     * @return true if it does, otherwise false
     */
    public final boolean hasIp(@NonNull String ip) {
        return ips.containsKey(ip);
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
     * Purge all expired IPs.
     *
     * @see #ipExpiration for expiration
     */
    public void purgeExpiredIps() {
        boolean removed = ips.entrySet().removeIf(entry -> (System.currentTimeMillis() - entry.getValue()) >= ipExpiration);
        if (removed) { // Did we remove anything?
            dirty = true; // Mark as dirty
            log("Purged expired IPs");
        }
    }
    
    /**
     * Save the storage file for this provider.
     *
     * @see #storageFile for storage file
     */
    public void save() {
        if (!dirty) { // Not dirty, no need to save
            return;
        }
        try {
            if (!storageFile.exists()) { // Create the storage file if it doesn't exist
                File parent = storageFile.getParentFile();
                if (parent != null && (!parent.exists())) { // Make the parent if it doesn't exist
                    parent.mkdirs();
                }
                storageFile.createNewFile();
            }
            JsonObject jsonObject = new JsonObject();
            
            // Adding the IPs to the storage
            JsonObject ipsJsonObject = new JsonObject();
            for (Map.Entry<String, Long> entry : ips.entrySet()) {
                ipsJsonObject.addProperty(entry.getKey(), entry.getValue());
            }
            jsonObject.add("ips", ipsJsonObject);
            
            // Write the json to the storage file
            try (FileWriter fileWriter = new FileWriter(storageFile)) {
                fileWriter.write(AntiVPN.GSON.toJson(jsonObject));
                log("Saved storage file"); // Log that we saved the storage file
                dirty = false; // Remove the dirty flag
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
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