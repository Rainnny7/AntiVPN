package me.braydon.antivpn.provider.scrape;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import me.braydon.antivpn.provider.ServiceProvider;

import java.util.function.BooleanSupplier;

/**
 * A scrape task for a {@link ServiceProvider}.
 *
 * @author Braydon
 */
@RequiredArgsConstructor
public class ScrapeTask {
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
