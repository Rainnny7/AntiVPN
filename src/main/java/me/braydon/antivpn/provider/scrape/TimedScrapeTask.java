package me.braydon.antivpn.provider.scrape;

import lombok.NonNull;

/**
 * @author Braydon
 */
public class TimedScrapeTask extends ScrapeTask {
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
        lastRun = System.currentTimeMillis();
        super.run();
    }
}
