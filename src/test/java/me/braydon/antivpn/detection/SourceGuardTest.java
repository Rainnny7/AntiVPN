package me.braydon.antivpn.detection;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SourceGuardTest {
    private static List<String> addresses(int count) {
        List<String> addresses = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            addresses.add("45.%d.%d.1".formatted(i / 256, i % 256));
        }
        return addresses;
    }
    
    @Test
    void acceptsCleanLists() {
        SourceGuard.Result result = SourceGuard.check(List.of("1.2.3.0/24", "2a04:27c0::/32", "8.8.8.8"), 0, 0.5, 0.01);
        
        assertThat(result.isRejected()).isFalse();
        assertThat(result.accepted()).hasSize(3);
    }
    
    @Test
    void rejectsEmptyAndGarbageResponses() {
        assertThat(SourceGuard.check(List.of(), 0, 0.5, 0.01).isRejected()).isTrue();
        assertThat(SourceGuard.check(List.of("<html>", "<body>Service Unavailable</body>"), 0, 0.5, 0.01).isRejected()).isTrue();
    }
    
    @Test
    void rejectsListsThatShrinkTooMuch() {
        assertThat(SourceGuard.check(addresses(40), 100, 0.5, 0.01).isRejected()).isTrue();
        assertThat(SourceGuard.check(addresses(60), 100, 0.5, 0.01).isRejected()).isFalse();
    }
    
    @Test
    void dropsAFewUnsafeEntries() {
        List<String> entries = addresses(200);
        entries.add("0.0.0.0/0"); // Would match every IPv4 address
        
        SourceGuard.Result result = SourceGuard.check(entries, 0, 0.5, 0.01);
        
        assertThat(result.isRejected()).isFalse();
        assertThat(result.accepted()).hasSize(200);
        assertThat(result.unsafe()).containsExactly("0.0.0.0/0");
    }
    
    @Test
    void rejectsListsWithManyUnsafeEntries() {
        List<String> entries = new ArrayList<>(addresses(10));
        entries.add("10.0.0.0/8");
        entries.add("192.168.1.1");
        
        assertThat(SourceGuard.check(entries, 0, 0.5, 0.01).isRejected()).isTrue();
    }
    
    @Test
    void flagsBroadAndReservedBlocksAsUnsafe() {
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("4.0.0.0/7").orElseThrow())).isTrue();
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("4.0.0.0/8").orElseThrow())).isFalse();
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("2a00::/12").orElseThrow())).isTrue();
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("2a00::/24").orElseThrow())).isFalse();
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("172.16.0.0/12").orElseThrow())).isTrue();
        assertThat(SourceGuard.isUnsafe(me.braydon.antivpn.common.IPUtils.parse("fe80::1").orElseThrow())).isTrue();
    }
}
