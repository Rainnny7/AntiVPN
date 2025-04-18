package me.braydon.antivpn.provider;

import lombok.Getter;
import lombok.NonNull;
import me.braydon.antivpn.common.BloomFilter;
import me.braydon.antivpn.common.ReservoirSampler;
import me.braydon.antivpn.common.StringUtils;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.model.ServiceProviderIp;
import me.braydon.antivpn.provider.scrape.ScrapeTask;
import me.braydon.antivpn.repository.ServiceProviderRepository;
import org.apache.logging.log4j.Level;
import org.apache.logging.slf4j.SLF4JLogger;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Represents a service provider.
 *
 * @author Braydon
 */
@Getter
public abstract class ServiceProvider {
    /**
     * The registered {@link ServiceProvider}'s.
     */
    @Getter private static final Set<ServiceProvider> registry = Collections.synchronizedSet(new HashSet<>());
    
    /**
     * The id of this provider.
     */
    private final int id;
    
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
     * The {@link BloomFilter} to use for
     * IPs that belong to this provider.
     */
    private BloomFilter bloomFilter;
    
    /**
     * The service provider repository.
     *
     * @see ServiceProviderRepository for service provider repository
     */
    @Autowired @NonNull private ServiceProviderRepository serviceProviderRepository;
    
    /**
     * The scrape tasks for this provider.
     *
     * @see ScrapeTask for scrape task
     */
    @NonNull private final Set<ScrapeTask> scrapeTasks = Collections.synchronizedSet(new LinkedHashSet<>());
    
    /**
     * The metrics service instance to use.
     *
     * @see MetricService for metrics service
     */
    @Autowired @NonNull private MetricService metrics;
    
    /**
     * The scraped IPs.
     * <p>
     * This just acts as a cache so we don't flood the database
     * with a query each additional IP added, and instead we can
     * just add them in bulk.
     * </p>
     */
    @NonNull private final Set<String> scrapedIps = Collections.synchronizedSet(new TreeSet<>());
    
    /**
     * The logger to use for this provider.
     *
     * @see SLF4JLogger for logger
     */
    @NonNull private final SLF4JLogger logger;
    
    public ServiceProvider(int id, @NonNull String name, long ipExpiration) {
        this.id = id;
        this.name = name;
        this.ipExpiration = ipExpiration;
        logger = (SLF4JLogger) org.apache.logging.log4j.LogManager.getLogger(name); // Setup the logger
        registry.add(this); // Register this provider
    }
    
    @PostConstruct
    public void load() {
        List<String> allIps = serviceProviderRepository.getIps(getId());
        
        int subsetSize = 1000;
        ReservoirSampler sampler = new ReservoirSampler(subsetSize);
        
        // Sample each IP with a probability of subsetSize/allIps.size()
        for (int i = 0; i < allIps.size(); i++) {
            String ip = allIps.get(i);
            if (ip == null) { // Ignore empty elements
                continue;
            }
            sampler.sample(ip, i);
        }
        
        // Get the selected subset of IPs from the sampler
        String[] subset = sampler.getReservoir();
        
        // Create a Bloom filter with capacity based on the subset size and desired false positive rate
        double falsePositiveRate = 0.01;
        int capacity = (int) Math.ceil(subsetSize / (-Math.log(1 - Math.pow(falsePositiveRate, 1.0 / subsetSize))));
        bloomFilter = new BloomFilter(capacity); // Setup the bloom filter
        
        // Add the selected subset of IPs to the Bloom filter
        for (String ip : subset) {
            if (ip == null) { // Ignore empty elements
                continue;
            }
            bloomFilter.add(ip);
            System.out.println("ip from subset = " + ip);
        }
        log("Loaded {} IPs into the Bloom filter", subset.length); // Log the amount of IPs loaded into the Bloom filter
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
        if (hasIp(ip)) { // We already have this IP, ignore it
            return;
        }
        scrapedIps.add(ip); // Add the IP
        bloomFilter.add(ip); // Add the IP to the bloom filter
    }
    
    /**
     * Check if this provider has
     * the given IP address.
     *
     * @param ip the ip
     * @return true if it does, otherwise false
     */
    public final boolean hasIp(@NonNull String ip) {
        if (bloomFilter.contains(ip)) { // Check if the IP is in the bloom filter first
            return true;
        }
        if (scrapedIps.contains(ip)) { // We scraped this IP recently
            return true;
        }
//        return serviceProviderRepository.existsByIp(ip); // Is the IP stored in the database?
        return false;
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
            
            long before = System.currentTimeMillis();
            try {
                // Getting the IP addresses to insert as models
                List<ServiceProviderIp> ips = Collections.synchronizedList(new ArrayList<>());
                for (String ip : scrapedIps) {
                    ServiceProviderIp serviceProviderIp = new ServiceProviderIp();
                    serviceProviderIp.setProvider(getId()); // Set the id of the provider
                    serviceProviderIp.setIp(ip); // Set the serialized ip
                    ips.add(serviceProviderIp);
                }
                int batchSize = 1000; // The amount of IPs to insert at a time
                AtomicInteger currentRound = new AtomicInteger();
                int rounds = ips.size() / batchSize; // The amount of rounds we need to do
                
                ExecutorService bob = Executors.newFixedThreadPool(59);
                for (int i = 0; i < rounds; i++) {
                    List<ServiceProviderIp> batch = ips.subList(i * batchSize, (i + 1) * batchSize);
                    bob.execute(() -> { // Offload the database insertion to another thread
                        log("Inserting {} IPs into the database on thread {}, round {}/{}", // Log the batch we're inserting
                            batch.size(), Thread.currentThread().getName(), currentRound.get() + 1, rounds
                        );
                        long beforeInsert = System.currentTimeMillis(); // Before we insert
                        serviceProviderRepository.saveAll(batch); // Insert the current batch
                        
                        // Log that we finished inserting for this round
                        log("Inserted {} IPs into the database in {}ms, round {}/{}",
                            batch.size(), System.currentTimeMillis() - beforeInsert, currentRound.get() + 1, rounds
                        );
                        currentRound.incrementAndGet(); // Increment the round
                    });
                }
                // Sleep for as long as we're running the database queries
                while (currentRound.get() < rounds) {
                    try {
                        Thread.sleep(100L);
                    } catch (InterruptedException ex) {
                        ex.printStackTrace();
                    }
                }
                // Batch cleanup
                //                if (batch != null) {
                //                    if (!batch.isEmpty()) { // Save the remaining IPs
                //                        serviceProviderRepository.saveAll(batch);
                //                    }
                //                    batch.clear(); // Clear the batch
                //                }
                // Log the IPs being added
                log("Successfully inserted {} IPs into the database, took {}ms",
                    StringUtils.formatNumber(scrapedIps.size()), System.currentTimeMillis() - before
                );
            } finally {
                metrics.getTracker(DatabaseTracker.class).submitResponseTime(
                    DatabaseTracker.DatabaseType.MONGODB, System.currentTimeMillis() - before); // Metrics
                scrapedIps.clear(); // Clear the scraped IPs after we've inserted them
            }
        }
    }
    
    /**
     * Get the amount of IPs this
     * service provider has.
     *
     * @param includeScraped whether or not to include the scraped IPs
     * @return the amount of IPs
     */
    public final int getIps(boolean includeScraped) {
        return serviceProviderRepository.getIpCount(getId()) + (includeScraped ? scrapedIps.size() : 0);
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
}