package me.braydon.antivpn.detection;

import inet.ipaddr.IPAddress;
import me.braydon.antivpn.common.IPUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.TaskScheduler;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class DetectionServiceTest {
    @TempDir Path snapshotDirectory;
    
    private DetectionProperties properties;
    private FakeSource vpn;
    private FakeSource rotating;
    
    @BeforeEach
    void setUp() {
        properties = new DetectionProperties();
        properties.setSchedulingEnabled(false);
        properties.setSnapshotDirectory(snapshotDirectory);
        vpn = new FakeSource("fake-vpn", Category.VPN, null, List.of("198.51.99.0/24", "2a04:27c0::/32"));
        rotating = new FakeSource("fake-dns", Category.VPN, Duration.ofDays(14L), List.of("45.1.1.1"));
    }
    
    private DetectionService service() {
        @SuppressWarnings("unchecked")
        ObjectProvider<TaskScheduler> scheduler = mock(ObjectProvider.class);
        DetectionService service = new DetectionService(List.of(vpn, rotating), properties, new SnapshotStore(properties),
            new HostingAsns(Map.of(14061L, "DigitalOcean")), scheduler);
        service.initialize();
        return service;
    }
    
    private static IPAddress ip(String input) {
        return IPUtils.parseAddress(input).orElseThrow();
    }
    
    @Test
    void matchesAfterARefresh() {
        DetectionService service = service();
        assertThat(service.lookup(ip("198.51.99.7"), null)).isEmpty();
        
        assertThat(service.refresh("fake-vpn")).isTrue();
        
        assertThat(service.lookup(ip("198.51.99.7"), null))
            .containsExactly(new Detection("fake-vpn", "fake-vpn", Category.VPN, Confidence.CONFIRMED, "198.51.99.0/24"));
        assertThat(service.lookup(ip("2a04:27c0::1"), null)).hasSize(1);
        assertThat(service.lookup(ip("198.51.98.7"), null)).isEmpty();
    }
    
    @Test
    void matchesHostingAsns() {
        DetectionService service = service();
        
        assertThat(service.lookup(ip("45.55.1.1"), 14061L))
            .containsExactly(new Detection("hosting-asn", "DigitalOcean", Category.HOSTING, Confidence.LIKELY, "AS14061"));
        assertThat(service.lookup(ip("45.55.1.1"), 7018L)).isEmpty();
    }
    
    @Test
    void keepsLastGoodDataWhenAFetchFails() {
        DetectionService service = service();
        service.refresh("fake-vpn");
        
        vpn.failure = new IllegalStateException("upstream is down");
        assertThat(service.refresh("fake-vpn")).isFalse();
        
        assertThat(service.lookup(ip("198.51.99.7"), null)).hasSize(1);
        assertThat(service.findState("fake-vpn").orElseThrow().getLastError()).contains("upstream is down");
    }
    
    @Test
    void keepsLastGoodDataWhenARefreshShrinksTooMuch() {
        vpn.entries = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            vpn.entries.add("45.0.0." + (i + 1));
        }
        DetectionService service = service();
        service.refresh("fake-vpn");
        
        vpn.entries = List.of("45.0.0.1");
        assertThat(service.refresh("fake-vpn")).isFalse();
        
        assertThat(service.lookup(ip("45.0.0.50"), null)).hasSize(1);
    }
    
    @Test
    void ignoresStaleSources() {
        DetectionService service = service();
        service.apply("fake-vpn", List.of("198.51.99.0/24"), Instant.now().minus(Duration.ofDays(30L)));
        
        assertThat(service.lookup(ip("198.51.99.7"), null)).isEmpty();
        assertThat(service.isStale(service.findState("fake-vpn").orElseThrow(), Instant.now())).isTrue();
    }
    
    @Test
    void accumulatesEntriesWithinTheRetention() {
        DetectionService service = service();
        Instant now = Instant.now();
        service.apply("fake-dns", List.of("45.1.1.1"), now.minus(Duration.ofDays(20L)));
        service.apply("fake-dns", List.of("45.1.1.2"), now.minus(Duration.ofDays(5L)));
        service.apply("fake-dns", List.of("45.1.1.3"), now);
        
        assertThat(service.lookup(ip("45.1.1.1"), null)).isEmpty(); // expired
        assertThat(service.lookup(ip("45.1.1.2"), null)).hasSize(1);
        assertThat(service.lookup(ip("45.1.1.3"), null)).hasSize(1);
    }
    
    @Test
    void restoresFromSnapshotsAfterARestart() {
        service().refresh("fake-vpn");
        
        vpn.failure = new IllegalStateException("offline");
        DetectionService restarted = service();
        
        assertThat(restarted.lookup(ip("198.51.99.7"), null)).hasSize(1);
    }
    
    @Test
    void bumpsTheGenerationWhenDataChanges() {
        DetectionService service = service();
        long before = service.getGeneration();
        
        service.refresh("fake-vpn");
        
        assertThat(service.getGeneration()).isGreaterThan(before);
    }
    
    @Test
    void skipsDisabledSources() {
        properties.setDisabledSources(List.of("fake-vpn"));
        DetectionService service = service();
        
        assertThat(service.findState("fake-vpn")).isEmpty();
        assertThat(service.findState("fake-dns")).isPresent();
    }
    
    private static final class FakeSource extends DetectionSource {
        private final Duration retention;
        private List<String> entries;
        private RuntimeException failure;
        
        FakeSource(String id, Category category, Duration retention, List<String> entries) {
            super(id, id, category, Confidence.CONFIRMED, Duration.ofHours(1L));
            this.retention = retention;
            this.entries = entries;
        }
        
        @Override
        public List<String> fetch() {
            if (failure != null) {
                throw failure;
            }
            return entries;
        }
        
        @Override
        public Duration getRetention() {
            return retention;
        }
    }
}
