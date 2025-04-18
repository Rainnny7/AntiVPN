package me.braydon.antivpn.common;

import lombok.Getter;
import lombok.NonNull;

import java.util.Random;

/**
 * @author Braydon
 * @see <a href="https://en.wikipedia.org/wiki/Reservoir_sampling">Reservoir Sampling</a>
 */
public class ReservoirSampler {
    /**
     * The reservoir of items.
     */
    @NonNull @Getter private final String[] reservoir;
    
    /**
     * The {@link Random} instance to use.
     */
    @NonNull private final Random random = new Random();
    
    public ReservoirSampler(int size) {
        this.reservoir = new String[size];
    }
    
    /**
     * Sample the given item at the given index.
     *
     * @param item  the item
     * @param index the index
     */
    public void sample(@NonNull String item, long index) {
        if (index < reservoir.length) { // Fill the reservoir with the first k items
            reservoir[(int) index] = item;
        } else { // Replace a random item in the reservoir with probability k/index
            int randomIndex = random.nextInt((int) index);
            if (randomIndex < reservoir.length) {
                reservoir[randomIndex] = item;
            }
        }
    }
}
