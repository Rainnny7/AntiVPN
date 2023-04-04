package me.braydon.antivpn.metrics.impl;

import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import lombok.NonNull;
import me.braydon.antivpn.metrics.MetricTracker;
import me.braydon.antivpn.provider.VPNServiceProvider;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * @author Braydon
 */
public final class ProviderTracker extends MetricTracker {
    public ProviderTracker() {
        super(TimeUnit.SECONDS.toMillis(10L));
    }
    
    /**
     * Execute this tracker.
     * <p>
     * This method will only
     * be invoked at the given
     * interval for this tracker.
     * </p>
     *
     * @param chain the chain of points to attach to
     * @see Point for point
     */
    @Override
    public void track(@NonNull List<Point> chain) {
        Set<VPNServiceProvider> providers = VPNServiceProvider.getRegistry();
        
        // IP Addresses
        for (VPNServiceProvider provider : providers) {
            chain.add(Point.measurement("providerIps")
                          .addTag("provider", provider.getName())
                          .addField("value", ThreadLocalRandom.current().nextInt(100, 1000)) // TODO: impl into cache, too intense to do now
                          .time(Instant.now().toEpochMilli(), WritePrecision.MS));
        }
    }
}