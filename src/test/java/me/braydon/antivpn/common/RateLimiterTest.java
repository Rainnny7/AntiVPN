package me.braydon.antivpn.common;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterTest {
    @Test
    void allowsUpToTheLimit() {
        RateLimiter rateLimiter = new RateLimiter(3, TimeUnit.HOURS);
        
        assertThat(rateLimiter.tryAcquire()).isTrue();
        assertThat(rateLimiter.tryAcquire()).isTrue();
        assertThat(rateLimiter.tryAcquire()).isTrue();
        assertThat(rateLimiter.tryAcquire()).isFalse();
    }
    
    @Test
    void refillsOverTime() throws InterruptedException {
        RateLimiter rateLimiter = new RateLimiter(20, TimeUnit.SECONDS);
        for (int i = 0; i < 20; i++) {
            assertThat(rateLimiter.tryAcquire()).isTrue();
        }
        assertThat(rateLimiter.tryAcquire()).isFalse();
        
        Thread.sleep(200L); // 20 tokens per second, so ~4 tokens
        assertThat(rateLimiter.tryAcquire()).isTrue();
    }
    
    @Test
    void refillsUnderConstantTraffic() throws InterruptedException {
        RateLimiter rateLimiter = new RateLimiter(10, TimeUnit.SECONDS); // A token every 100ms
        for (int i = 0; i < 10; i++) {
            rateLimiter.tryAcquire();
        }
        
        // Polling more often than a token is added must not starve the bucket
        boolean acquired = false;
        for (int i = 0; i < 30 && !acquired; i++) {
            Thread.sleep(20L);
            acquired = rateLimiter.tryAcquire();
        }
        assertThat(acquired).isTrue();
    }
    
    @Test
    void restrictsBeforeDisabling() {
        RateLimiter rateLimiter = new RateLimiter(1, TimeUnit.HOURS);
        assertThat(rateLimiter.tryAcquire()).isTrue();
        for (int i = 0; i < 15; i++) {
            assertThat(rateLimiter.tryAcquire()).isFalse();
        }
        assertThat(rateLimiter.isDisabled()).isFalse(); // First offense only restricts
        
        for (int i = 0; i < 15; i++) {
            assertThat(rateLimiter.tryAcquire()).isFalse();
        }
        assertThat(rateLimiter.isDisabled()).isTrue();
    }
}
