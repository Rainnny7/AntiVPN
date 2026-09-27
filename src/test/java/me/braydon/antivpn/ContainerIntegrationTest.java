package me.braydon.antivpn;

import me.braydon.antivpn.detection.source.NordVpnSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mariadb.MariaDBContainer;

import java.time.Instant;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The application against real MariaDB and Redis, skipped when Docker isn't available.
 */
@Testcontainers(disabledWithoutDocker = true)
class ContainerIntegrationTest extends AbstractApplicationTest {
    @Container @ServiceConnection
    static final MariaDBContainer MARIADB = new MariaDBContainer("mariadb:11.4");
    
    @Container @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
    
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        snapshotDirectory(registry);
    }
    
    @Test
    void cachesLookups() throws Exception {
        check("1.128.0.2").andExpect(status().isOk()).andExpect(jsonPath("$.cached").doesNotExist());
        check("1.128.0.2").andExpect(status().isOk()).andExpect(jsonPath("$.cached").isNumber());
    }
    
    @Test
    void bypassesTheCacheWhenAsked() throws Exception {
        check("1.128.0.3");
        check("1.128.0.3", "ignoreCache", "true").andExpect(jsonPath("$.cached").doesNotExist());
    }
    
    @Test
    void recomputesWhenMoreDataIsRequested() throws Exception {
        check("1.128.0.4");
        check("1.128.0.4", "data", "ASN")
            .andExpect(jsonPath("$.cached").doesNotExist())
            .andExpect(jsonPath("$.asn.number").value(1221));
        check("1.128.0.4", "data", "ASN").andExpect(jsonPath("$.cached").isNumber());
    }
    
    @Test
    void invalidatesTheCacheWhenSourcesChange() throws Exception {
        check("89.35.28.131").andExpect(jsonPath("$.vpn").value(true));
        check("89.35.28.131").andExpect(jsonPath("$.cached").isNumber());
        
        detectionService.apply("nordvpn", NordVpnSource.parse(Fixtures.read("nordvpn.json")), Instant.now());
        
        check("89.35.28.131").andExpect(jsonPath("$.cached").doesNotExist()).andExpect(jsonPath("$.vpn").value(true));
    }
}
