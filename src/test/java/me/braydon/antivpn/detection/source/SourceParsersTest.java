package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.Fixtures;
import me.braydon.antivpn.detection.SourceGuard;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SourceParsersTest {
    private static void assertAllValid(List<String> entries) {
        SourceGuard.Result result = SourceGuard.check(entries, 0, 0.5, 0.01);
        assertThat(result.isRejected()).isFalse();
        assertThat(result.invalid()).isZero();
        assertThat(result.unsafe()).isEmpty();
    }
    
    @Test
    void parsesNordVpn() {
        List<String> entries = NordVpnSource.parse(Fixtures.read("nordvpn.json"));
        
        assertThat(entries).containsExactly("89.35.28.131", "89.34.98.195", "195.206.180.3", "2a0d:5600:24:44::4", "185.216.34.227");
        assertAllValid(entries);
    }
    
    @Test
    void parsesPia() {
        List<String> entries = PiaSource.parse(Fixtures.read("pia.txt"));
        
        assertThat(entries).containsExactlyInAnyOrder("37.19.197.230", "37.19.197.168", "37.19.197.219", "37.19.197.220", "212.102.57.138");
        assertAllValid(entries);
    }
    
    @Test
    void parsesMullvadSkippingBridgesAndInactiveRelays() {
        List<String> entries = MullvadSource.parse(Fixtures.read("mullvad.json"));
        
        assertThat(entries).containsExactly("103.124.165.2", "2a04:27c0:0:e::f001", "185.213.154.66");
        assertAllValid(entries);
    }
    
    @Test
    void parsesSurfsharkHostnames() {
        assertThat(SurfsharkSource.parse(Fixtures.read("surfshark.json")))
            .containsExactly("al-tia.prod.surfshark.com", "de-fra.prod.surfshark.com");
    }
    
    @Test
    void parsesTor() {
        List<String> entries = PlainListSource.parse(Fixtures.read("tor.txt"));
        
        assertThat(entries).hasSize(5).contains("171.25.193.25", "2001:67c:e60:c0c:192:42:116:16");
        assertAllValid(entries);
    }
    
    @Test
    void parsesPlainListsWithComments() {
        assertThat(PlainListSource.parse("# header\n1.2.3.0/24 ; SBL123\n\n  5.6.7.8  \n2001:db9::/32 # comment\r\n9.9.9.9,extra"))
            .containsExactly("1.2.3.0/24", "5.6.7.8", "2001:db9::/32", "9.9.9.9");
    }
    
    @Test
    void parsesSpamhausDropSkippingMetadata() {
        List<String> entries = SpamhausDropSource.parse(Fixtures.read("spamhaus-drop-v4.json"));
        
        assertThat(entries).containsExactly("1.10.16.0/20", "1.19.0.0/16", "2.56.192.0/22");
        assertAllValid(entries);
    }
    
    @Test
    void parsesAws() {
        List<String> entries = AwsSource.parse(Fixtures.read("aws.json"));
        
        assertThat(entries).containsExactly("3.4.12.4/32", "3.5.140.0/22", "2600:1f14::/35");
        assertAllValid(entries);
    }
    
    @Test
    void parsesGcp() {
        List<String> entries = GcpSource.parse(Fixtures.read("gcp.json"));
        
        assertThat(entries).containsExactly("34.1.208.0/20", "34.35.0.0/16", "2600:1900:8000::/44");
        assertAllValid(entries);
    }
    
    @Test
    void parsesICloudPrivateRelay() {
        List<String> entries = ICloudPrivateRelaySource.parse(Fixtures.read("icloud-private-relay.csv"));
        
        assertThat(entries).containsExactly("172.224.226.0/27", "172.224.226.32/31", "104.28.0.0/24", "2a02:26f7:b3c0:4000::/64");
        assertAllValid(entries);
    }
    
    @Test
    void parsesX4b() {
        List<String> entries = PlainListSource.parse(Fixtures.read("x4b.txt"));
        
        assertThat(entries).hasSize(4);
        assertAllValid(entries);
    }
}
