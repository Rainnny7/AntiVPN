package me.braydon.antivpn.common;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IPUtilsTest {
    @ParameterizedTest
    @ValueSource(strings = { "999.1.1.1", "1.2.3", "1.2.3.4.5", "abc", "", " ", "1.2.3.4/24", "2001:db8::/32", "::g", "*", "1.2.3.*", "1.2.3.1-5", "16909060", "0x01.2.3.4" })
    void rejectsInvalidAddresses(String input) {
        assertThat(IPUtils.getIpType(input)).isEqualTo(-1);
        assertThat(IPUtils.parseAddress(input)).isEmpty();
    }
    
    @Test
    void detectsIpTypes() {
        assertThat(IPUtils.getIpType("1.1.1.1")).isEqualTo(4);
        assertThat(IPUtils.getIpType(" 8.8.4.4 ")).isEqualTo(4);
        assertThat(IPUtils.getIpType("2606:4700:4700::1111")).isEqualTo(6);
        assertThat(IPUtils.getIpType("2606:4700:4700:0000:0000:0000:0000:1111")).isEqualTo(6);
    }
    
    @Test
    void normalizesIpv4MappedAddresses() {
        assertThat(IPUtils.parseAddress("::ffff:1.2.3.4").orElseThrow().toCanonicalString()).isEqualTo("1.2.3.4");
        assertThat(IPUtils.getIpType("::ffff:1.2.3.4")).isEqualTo(4);
    }
    
    @ParameterizedTest
    @ValueSource(strings = {
        "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255",
        "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250",
        "240.0.0.1", "255.255.255.255",
        "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"
    })
    void detectsReservedAddresses(String input) {
        assertThat(IPUtils.isReserved(IPUtils.parseAddress(input).orElseThrow())).isTrue();
    }
    
    @ParameterizedTest
    @ValueSource(strings = { "1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "81.2.69.142", "2606:4700:4700::1111", "2a00:1450:4001::1" })
    void allowsPublicAddresses(String input) {
        assertThat(IPUtils.isReserved(IPUtils.parseAddress(input).orElseThrow())).isFalse();
    }
    
    @Test
    void detectsBlocksOverlappingReservedSpace() {
        assertThat(IPUtils.isReserved(IPUtils.parse("8.0.0.0/6").orElseThrow())).isTrue(); // contains 10/8
        assertThat(IPUtils.isReserved(IPUtils.parse("8.8.8.0/24").orElseThrow())).isFalse();
    }
}
