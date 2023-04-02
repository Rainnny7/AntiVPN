package me.braydon.antivpn.common;

import lombok.Getter;
import lombok.Setter;

import java.util.concurrent.TimeUnit;

/**
 * This class represents a rate limiter with a token bucket algorithm.
 *
 * @author the cool ai man named ChatGPT
 */
public class RateLimiter {
    private static final int MAX_FAILED_ATTEMPTS = 15; // The max amount of failed attempts before the rate limiter is restricted
    
    @Setter @Getter private int maxTokens; // the maximum number of tokens in the bucket
    private final TimeUnit refillIntervalTimeUnit; // the time unit for the refill interval
    private long tokens; // the current number of tokens in the bucket
    private long lastRefillTimestamp; // the timestamp of the last bucket refill
    
    /**
     * The amount of time the {#link #tryAcquire()}
     * method has failed to acquire a token.
     */
    private int failedAttempts;
    
    /**
     * Was this rate limiter previously restricted?
     */
    private boolean previouslyRestricted;
    
    /**
     * Whether this rate limiter is disabled.
     */
    @Getter private boolean disabled;
    
    /**
     * Creates a new rate limiter with the specified parameters.
     *
     * @param maxTokens              the maximum number of tokens in the bucket
     * @param refillIntervalTimeUnit the time unit for the refill interval
     */
    public RateLimiter(int maxTokens, TimeUnit refillIntervalTimeUnit) {
        this.maxTokens = maxTokens;
        this.refillIntervalTimeUnit = refillIntervalTimeUnit;
        this.tokens = maxTokens; // initially the bucket is full
        lastRefillTimestamp = System.currentTimeMillis(); // initial timestamp is the current time
    }
    
    /**
     * Attempts to acquire a token from the bucket. If the bucket is empty, this method blocks until a token is available.
     *
     * @return true if a token was acquired, false otherwise
     */
    public synchronized boolean tryAcquire() {
        refill(); // refill the bucket if needed
        if (isDisabled()) { // Is the rate limiter restricted?
            return false;
        } else if (tokens > 0) { // check if there are tokens available
            tokens--; // decrement the token count
            failedAttempts = 0; // Reset the failed attempts
            previouslyRestricted = true; // We are now restricted
            return true; // allow the request
        } else {
            if (++failedAttempts >= MAX_FAILED_ATTEMPTS) { // Reached our max failed attempts
                if (previouslyRestricted) { // If we were previously restricted, disable the rate limiter
                    disabled = true;
                    return false;
                }
                // Restricting the rate limiter
                failedAttempts = 0; // Reset the failed attempts
                previouslyRestricted = true; // We are now restricted
            }
            return false; // block the request
        }
    }
    
    /**
     * Refills the bucket with tokens based on the time elapsed since the last refill.
     */
    private void refill() {
        long currentTime = System.currentTimeMillis(); // Cet the current time
        long elapsedTime = currentTime - lastRefillTimestamp; // Calculate the time elapsed since the last refill
        long tokensToAdd = elapsedTime * maxTokens / refillIntervalTimeUnit.toMillis(1L); // Calculate how many tokens should be added based on the elapsed time and the refill interval
        tokens = Math.min(tokens + tokensToAdd, maxTokens); // Add the tokens while ensuring the bucket doesn't exceed its maximum capacity
        lastRefillTimestamp = currentTime; // update the last refill timestamp
    }
}