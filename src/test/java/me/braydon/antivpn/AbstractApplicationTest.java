package me.braydon.antivpn;

import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.detection.source.ICloudPrivateRelaySource;
import me.braydon.antivpn.detection.source.NordVpnSource;
import me.braydon.antivpn.detection.source.PlainListSource;
import me.braydon.antivpn.detection.source.SpamhausDropSource;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.APIKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Runs lookups through the whole application with fixture data
 * loaded into the detection sources, and the MaxMind test databases.
 * <p>
 * MaxMind test data: 1.128.0.0/11 and 2001:8000::/20 are Telstra (AS1221, residential),
 * 12.81.92.0/22 is AT&T (AS7018, configured as a hosting ASN here), 81.2.69.142 is London, GB.
 * </p>
 */
@SpringBootTest(properties = {
    "detection.scheduling-enabled=false",
    "detection.extra-hosting-asns=7018",
    "maxmind.directory=src/test/resources/maxmind",
    "maxmind.license=",
    "influxdb.url=",
    "logging.file.path=target/logs"
})
@AutoConfigureMockMvc
public abstract class AbstractApplicationTest {
    @Autowired protected MockMvc mvc;
    @Autowired protected DetectionService detectionService;
    @Autowired protected APIKeyRepository apiKeyRepository;
    
    protected String apiKey;
    
    protected static void snapshotDirectory(DynamicPropertyRegistry registry) {
        try {
            String directory = Files.createTempDirectory("antivpn-snapshots-").toString();
            registry.add("detection.snapshot-directory", () -> directory);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
    
    @BeforeEach
    void loadFixtures() {
        Instant now = Instant.now();
        detectionService.apply("nordvpn", NordVpnSource.parse(Fixtures.read("nordvpn.json")), now);
        detectionService.apply("tor", PlainListSource.parse(Fixtures.read("tor.txt")), now);
        detectionService.apply("spamhaus-drop", SpamhausDropSource.parse(Fixtures.read("spamhaus-drop-v4.json")), now);
        detectionService.apply("icloud-private-relay", ICloudPrivateRelaySource.parse(Fixtures.read("icloud-private-relay.csv")), now);
        detectionService.apply("x4b-datacenter", List.of("104.28.0.0/16", "5.157.0.0/16"), now);
        APIKey key = APIKey.generate(apiKeyRepository, "Test", APIKey.Permission.values());
        key.setRateLimits(new HashMap<>(Map.of(TimeUnit.SECONDS, 1000)));
        apiKey = apiKeyRepository.save(key).getSecret();
    }
    
    protected ResultActions check(String ip, String... params) throws Exception {
        var request = get("/check").param("ip", ip).header("X-API-Key", apiKey);
        for (int i = 0; i + 1 < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        return mvc.perform(request);
    }
    
    @Test
    void residentialAddressesAreClean() throws Exception {
        check("1.128.0.1", "data", "ASN")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.ip").value("1.128.0.1"))
            .andExpect(jsonPath("$.ipType").value(4))
            .andExpect(jsonPath("$.risk").value(0.0))
            .andExpect(jsonPath("$.vpn").value(false))
            .andExpect(jsonPath("$.hosting").value(false))
            .andExpect(jsonPath("$.detections").isEmpty())
            .andExpect(jsonPath("$.asn.number").value(1221))
            .andExpect(jsonPath("$.geographical").doesNotExist());
        
        check("2001:8000::1")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.ipType").value(6))
            .andExpect(jsonPath("$.risk").value(0.0));
    }
    
    @Test
    void vpnProviderServersAreFlagged() throws Exception {
        check("89.35.28.131")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.vpn").value(true))
            .andExpect(jsonPath("$.vpnProvider").value(true))
            .andExpect(jsonPath("$.provider").value("NordVPN"))
            .andExpect(jsonPath("$.risk").value(1.0));
        
        check("2a0d:5600:24:44::4").andExpect(jsonPath("$.provider").value("NordVPN"));
        check("::ffff:89.35.28.131").andExpect(jsonPath("$.ip").value("89.35.28.131")).andExpect(jsonPath("$.vpn").value(true));
    }
    
    @Test
    void neighboursOfVpnServersAreNotFlagged() throws Exception {
        check("89.35.28.130").andExpect(jsonPath("$.vpn").value(false)).andExpect(jsonPath("$.risk").value(0.0));
    }
    
    @Test
    void torExitsAreFlaggedAsTor() throws Exception {
        check("171.25.193.25")
            .andExpect(jsonPath("$.tor").value(true))
            .andExpect(jsonPath("$.vpn").value(false))
            .andExpect(jsonPath("$.risk").value(1.0));
    }
    
    @Test
    void abuseNetworksAreFlaggedAsAbuse() throws Exception {
        check("1.10.16.5")
            .andExpect(jsonPath("$.abuse").value(true))
            .andExpect(jsonPath("$.vpn").value(false))
            .andExpect(jsonPath("$.risk").value(0.9));
    }
    
    @Test
    void hostingAsnsAreHostingNotVpn() throws Exception {
        check("12.81.92.1")
            .andExpect(jsonPath("$.hosting").value(true))
            .andExpect(jsonPath("$.vpn").value(false))
            .andExpect(jsonPath("$.risk").value(0.5))
            .andExpect(jsonPath("$.detections[0].range").value("AS7018"));
    }
    
    @Test
    void privateRelayInsideADatacenterRangeIsOnlyARelay() throws Exception {
        check("104.28.0.9")
            .andExpect(jsonPath("$.relay").value(true))
            .andExpect(jsonPath("$.hosting").value(false))
            .andExpect(jsonPath("$.vpn").value(false))
            .andExpect(jsonPath("$.risk").value(0.1));
        
        // The rest of the datacenter range is still hosting
        check("104.28.1.9").andExpect(jsonPath("$.hosting").value(true)).andExpect(jsonPath("$.relay").value(false));
    }
    
    @Test
    void rejectsInvalidAndReservedAddresses() throws Exception {
        for (String ip : new String[] { "999.1.1.1", "1.2.3", "localhost", "not an ip" }) {
            check(ip).andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        }
        for (String ip : new String[] { "10.0.0.1", "127.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1" }) {
            check(ip).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Cannot lookup private or reserved IP ranges"));
        }
    }
    
    @Test
    void countryBlacklistRaisesRiskWithoutFlaggingAVpn() throws Exception {
        toggle("/blacklist/modify", "COUNTRY", "GB");
        try {
            check("81.2.69.142", "data", "GEOGRAPHICAL")
                .andExpect(jsonPath("$.geographical.countryIsoCode").value("GB"))
                .andExpect(jsonPath("$.geographical.city").value("London"))
                .andExpect(jsonPath("$.blacklists").value(hasItem("COUNTRY")))
                .andExpect(jsonPath("$.vpn").value(false))
                .andExpect(jsonPath("$.risk").value(0.4));
        } finally {
            toggle("/blacklist/modify", "COUNTRY", "GB");
        }
        check("81.2.69.142").andExpect(jsonPath("$.blacklists").value(not(hasItem("COUNTRY"))));
    }
    
    @Test
    void allowlistWins() throws Exception {
        toggle("/allowlist/modify", "IP_RANGE", "89.35.28.0/24");
        try {
            check("89.35.28.131")
                .andExpect(jsonPath("$.allowlisted").value(true))
                .andExpect(jsonPath("$.vpn").value(false))
                .andExpect(jsonPath("$.risk").value(0.0));
        } finally {
            toggle("/allowlist/modify", "IP_RANGE", "89.35.28.0/24");
        }
        check("89.35.28.131").andExpect(jsonPath("$.vpn").value(true));
    }
    
    @Test
    void reportsSourcesInStats() throws Exception {
        mvc.perform(get("/stats").header("X-API-Key", apiKey))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sources.nordvpn.blocks").value(5))
            .andExpect(jsonPath("$.sources.nordvpn.stale").value(false))
            .andExpect(jsonPath("$.sources.mullvad.stale").value(true))
            .andExpect(jsonPath("$.ips.total").isNumber());
    }
    
    @Test
    void requiresAnApiKey() throws Exception {
        mvc.perform(get("/check").param("ip", "1.128.0.1")).andExpect(status().isUnauthorized());
    }
    
    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
    }
    
    private void toggle(String route, String type, String entry) throws Exception {
        mvc.perform(post(route).param("type", type).param("entry", entry).header("X-API-Key", apiKey))
            .andExpect(status().isOk());
    }
}
