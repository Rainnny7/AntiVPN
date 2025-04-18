package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.SneakyThrows;

import java.security.MessageDigest;
import java.util.BitSet;

/**
 * @author Braydon
 * @see <a href="https://en.wikipedia.org/wiki/Bloom_filter">Bloom Filter</a>
 */
public class BloomFilter {
    public static final int DEFAULT_CAPACITY = 1_000_000; // The default capacity for bloom filters
    private static final int[] SEEDS = new int[] { 3, 5, 7, 11, 13, 17, 19, 23 };
    
    /**
     * The bitset storage for the bloom filter.
     *
     * @see BitSet for bitset
     */
    @NonNull private final BitSet bitSet;
    
    public BloomFilter() {
        this(DEFAULT_CAPACITY);
    }
    
    public BloomFilter(int capacity) {
        bitSet = new BitSet(capacity);
    }
    
    /**
     * Add the given value
     * to the bloom filter.
     *
     * @param value the value
     */
    public void add(@NonNull String value) {
        if (value.isEmpty()) { // Can't add empty values
            throw new IllegalArgumentException("Cannot add empty values");
        }
        for (int seed : SEEDS) {
            int index = hash(value, seed) % DEFAULT_CAPACITY;
            bitSet.set(index, true);
        }
    }
    
    /**
     * Check if the given value
     * is in the bloom filter.
     *
     * @param value the value
     * @return true if contains, otherwise false
     */
    public boolean contains(@NonNull String value) {
        if (value.isEmpty()) { // Doesn't contain empty values
            return false;
        }
        for (int seed : SEEDS) {
            int index = hash(value, seed) % DEFAULT_CAPACITY;
            if (!bitSet.get(index)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Hash the given value and set
     * the bits in the bitset.
     *
     * @param value the value to hash
     * @param seed  the seed to use
     * @return the hashed value
     */
    @SneakyThrows
    private int hash(@NonNull String value, int seed) {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest((value + seed).getBytes()); // Hash the value
        int result = 0;
        for (byte b : bytes) { // Convert the bytes to an integer
            result = (result << 1) + (b & 0xFF);
        }
        return Math.abs(result); // Return the absolute value
    }
}