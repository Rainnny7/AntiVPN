package me.braydon.antivpn.detection;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HostingAsnsTest {
    @Test
    void loadsTheBundledList() throws Exception {
        Map<Long, String> asns = HostingAsns.load();
        
        assertThat(asns).containsEntry(14061L, "DigitalOcean").containsKeys(16509L, 24940L, 16276L, 9009L);
    }
    
    @Test
    void excludesNetworksThatCarryConsumerTraffic() throws Exception {
        // Google, Microsoft, Cloudflare (WARP), Akamai and Fastly (Private Relay), Cogent, Telstra, AT&T
        assertThat(HostingAsns.load()).doesNotContainKeys(15169L, 8075L, 13335L, 20940L, 16625L, 36183L, 54113L, 174L, 1221L, 7018L);
    }
    
    @Test
    void includesConfiguredExtras() throws Exception {
        DetectionProperties properties = new DetectionProperties();
        properties.setExtraHostingAsns(List.of(64512L));
        
        assertThat(new HostingAsns(properties).get(64512L)).isPresent();
        assertThat(new HostingAsns(properties).get(14061L)).contains("DigitalOcean");
    }
}
