package me.braydon.antivpn.common;

import inet.ipaddr.IPAddress;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IpRangeIndexTest {
    private static IPAddress ip(String input) {
        return IPUtils.parse(input).orElseThrow();
    }
    
    @Test
    void findsAddressesAtBlockBoundaries() {
        IpRangeIndex index = IpRangeIndex.of(List.of("10.20.0.0/16", "192.0.2.128/25"));
        
        assertThat(index.find(ip("10.20.0.0"))).contains("10.20.0.0/16");
        assertThat(index.find(ip("10.20.255.255"))).contains("10.20.0.0/16");
        assertThat(index.find(ip("10.19.255.255"))).isEmpty();
        assertThat(index.find(ip("10.21.0.0"))).isEmpty();
        assertThat(index.find(ip("192.0.2.127"))).isEmpty();
        assertThat(index.find(ip("192.0.2.128"))).contains("192.0.2.128/25");
    }
    
    @Test
    void supportsSingleAddressesAndHostPrefixes() {
        IpRangeIndex index = IpRangeIndex.of(List.of("198.51.100.7", "198.51.100.9/32", "2001:db8::1/128"));
        
        assertThat(index.contains(ip("198.51.100.7"))).isTrue();
        assertThat(index.contains(ip("198.51.100.8"))).isFalse();
        assertThat(index.contains(ip("198.51.100.9"))).isTrue();
        assertThat(index.contains(ip("2001:db8::1"))).isTrue();
        assertThat(index.contains(ip("2001:db8::2"))).isFalse();
    }
    
    @Test
    void supportsIpv6() {
        IpRangeIndex index = IpRangeIndex.of(List.of("2a04:27c0::/32"));
        
        assertThat(index.find(ip("2a04:27c0:0:e::f001"))).contains("2a04:27c0::/32");
        assertThat(index.contains(ip("2a04:27c1::"))).isFalse();
        assertThat(index.contains(ip("2a04:27bf:ffff:ffff:ffff:ffff:ffff:ffff"))).isFalse();
    }
    
    @Test
    void keepsIpv4AndIpv6Apart() {
        IpRangeIndex index = IpRangeIndex.of(List.of("1.2.3.0/24"));
        
        assertThat(index.contains(ip("::102:304"))).isFalse();
        assertThat(index.contains(ip("::ffff:1.2.3.4"))).isTrue(); // IPv4-mapped is normalized to IPv4
    }
    
    @Test
    void dropsNestedAndDuplicateBlocks() {
        IpRangeIndex index = IpRangeIndex.of(List.of("10.0.0.0/8", "10.1.0.0/16", "10.1.2.3", "10.0.0.0/8", "11.0.0.0/8"));
        
        assertThat(index.size()).isEqualTo(2);
        assertThat(index.getBlocks()).containsExactly("10.0.0.0/8", "11.0.0.0/8");
        assertThat(index.find(ip("10.1.2.3"))).contains("10.0.0.0/8");
    }
    
    @Test
    void normalizesHostBitsInPrefixes() {
        IpRangeIndex index = IpRangeIndex.of(List.of("203.0.113.77/24"));
        
        assertThat(index.getBlocks()).containsExactly("203.0.113.0/24");
        assertThat(index.contains(ip("203.0.113.1"))).isTrue();
    }
    
    @Test
    void skipsInvalidEntries() {
        IpRangeIndex index = IpRangeIndex.of(List.of("not an ip", "", "999.1.1.1", "8.8.8.8"));
        
        assertThat(index.size()).isEqualTo(1);
    }
    
    @Test
    void detectsOverlaps() {
        IpRangeIndex index = IpRangeIndex.of(List.of("10.0.0.0/8", "192.168.1.0/24"));
        
        assertThat(index.overlaps(ip("8.0.0.0/6"))).isTrue(); // contains 10/8
        assertThat(index.overlaps(ip("10.5.0.0/16"))).isTrue(); // inside 10/8
        assertThat(index.overlaps(ip("192.168.0.0/16"))).isTrue(); // contains 192.168.1/24
        assertThat(index.overlaps(ip("192.168.2.0/24"))).isFalse();
        assertThat(index.overlaps(ip("11.0.0.0/8"))).isFalse();
    }
    
    @Test
    void emptyIndexMatchesNothing() {
        assertThat(IpRangeIndex.empty().contains(ip("1.1.1.1"))).isFalse();
        assertThat(IpRangeIndex.of(List.of()).size()).isZero();
    }
}
