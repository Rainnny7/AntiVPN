package me.braydon.antivpn.controller;

import me.braydon.antivpn.common.ClientIpResolver;
import me.braydon.antivpn.config.WebSecurityConfig;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.Detection;
import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.DatabaseTracker;
import me.braydon.antivpn.metric.impl.RequestTracker;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.model.AddressData;
import me.braydon.antivpn.repository.APIKeyRepository;
import me.braydon.antivpn.service.AddressService;
import me.braydon.antivpn.service.PolicyListService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = { AddressController.class, AllowlistController.class })
@Import({ WebSecurityConfig.class, ControllerSecurityTest.Mocks.class })
class ControllerSecurityTest {
    private static final String FULL_KEY = "full-key";
    private static final String BASIC_KEY = "basic-key";
    private static final String BANNED_KEY = "banned-key";
    
    @Autowired private MockMvc mvc;
    @Autowired private APIKeyRepository apiKeyRepository;
    @MockitoBean private AddressService addressService;
    @MockitoBean private DetectionService detectionService;
    @MockitoBean private PolicyListService policyListService;
    @MockitoBean private ClientIpResolver clientIpResolver;
    
    @BeforeEach
    void setUp() {
        Map<String, APIKey> keys = Map.of(
            FULL_KEY, key(FULL_KEY, false, APIKey.Permission.values()),
            BASIC_KEY, key(BASIC_KEY, false),
            BANNED_KEY, key(BANNED_KEY, true, APIKey.Permission.values())
        );
        when(apiKeyRepository.findById(anyString())).thenAnswer(invocation -> Optional.ofNullable(keys.get(invocation.<String>getArgument(0))));
        when(clientIpResolver.resolve(any())).thenAnswer(invocation -> UUID.randomUUID().toString());
    }
    
    private static APIKey key(String secret, boolean banned, APIKey.Permission... permissions) {
        APIKey apiKey = new APIKey();
        apiKey.setSecret(secret);
        apiKey.setDescription(secret);
        apiKey.setRateLimits(new HashMap<>(Map.of(TimeUnit.SECONDS, 1000)));
        apiKey.setPermissions(Set.of(permissions));
        apiKey.setBanned(banned ? new Date() : null);
        apiKey.setCreation(new Date());
        return apiKey;
    }
    
    private static AddressData nordAddress() {
        return new AddressData("89.35.28.131", 4, 1F, true, true, "NordVPN", false, false, false, false, false, Set.of(),
            List.of(new Detection("nordvpn", "NordVPN", Category.VPN, Confidence.CONFIRMED, "89.35.28.131")), null, null);
    }
    
    @Test
    void requiresAnApiKey() throws Exception {
        mvc.perform(get("/check").param("ip", "89.35.28.131"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.message").value("A valid API key is required in the X-API-Key header"));
    }
    
    @Test
    void rejectsUnknownKeys() throws Exception {
        mvc.perform(get("/check").param("ip", "89.35.28.131").header("X-API-Key", "nope"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void rejectsBannedKeys() throws Exception {
        mvc.perform(get("/check").param("ip", "89.35.28.131").header("X-API-Key", BANNED_KEY))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void returnsTheLookup() throws Exception {
        AddressData data = nordAddress();
        data.flagCached(1234L);
        when(addressService.lookup(eq("89.35.28.131"), any(), anyBoolean())).thenReturn(data);
        
        mvc.perform(get("/check").param("ip", "89.35.28.131").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.ip").value("89.35.28.131"))
            .andExpect(jsonPath("$.risk").value(1.0))
            .andExpect(jsonPath("$.vpn").value(true))
            .andExpect(jsonPath("$.vpnProvider").value(true))
            .andExpect(jsonPath("$.provider").value("NordVPN"))
            .andExpect(jsonPath("$.relay").value(false))
            .andExpect(jsonPath("$.detections[0].source").value("nordvpn"))
            .andExpect(jsonPath("$.detections[0].category").value("VPN"))
            .andExpect(jsonPath("$.cached").value(1234))
            .andExpect(jsonPath("$.asn").doesNotExist());
    }
    
    @Test
    void requiresPermissionToIgnoreTheCache() throws Exception {
        mvc.perform(get("/check").param("ip", "89.35.28.131").param("ignoreCache", "true").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.message").value("Lacking permissions"));
    }
    
    @Test
    void mapsLookupErrorsToJson() throws Exception {
        when(addressService.lookup(eq("10.0.0.1"), any(), anyBoolean()))
            .thenThrow(new APIException(HttpStatus.BAD_REQUEST, "Cannot lookup private or reserved IP ranges"));
        
        mvc.perform(get("/check").param("ip", "10.0.0.1").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.message").value("Cannot lookup private or reserved IP ranges"))
            .andExpect(jsonPath("$.path").value("/check"));
    }
    
    @Test
    void rejectsMissingAndInvalidParameters() throws Exception {
        mvc.perform(get("/check").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isBadRequest());
        mvc.perform(get("/check").param("ip", "1.1.1.1").param("data", "NOPE").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Invalid value for parameter 'data'"));
    }
    
    @Test
    void requiresPermissionForStats() throws Exception {
        mvc.perform(get("/stats").header("X-API-Key", BASIC_KEY)).andExpect(status().isForbidden());
        mvc.perform(get("/stats").header("X-API-Key", FULL_KEY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sources").exists());
    }
    
    @Test
    void requiresPermissionToManageAllowlists() throws Exception {
        mvc.perform(post("/allowlist/modify").param("type", "ASN").param("entry", "AS1221").header("X-API-Key", BASIC_KEY))
            .andExpect(status().isForbidden());
        
        when(policyListService.toggleAllowlist(any(), eq("AS1221"))).thenReturn(true);
        mvc.perform(post("/allowlist/modify").param("type", "ASN").param("entry", "AS1221").header("X-API-Key", FULL_KEY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Entry 'AS1221' was added"));
    }
    
    @Test
    void publicRoutesDoNotNeedAKey() throws Exception {
        mvc.perform(get("/amiusingavpn")).andExpect(status().isNotFound()); // Disabled by default
    }
    
    @Test
    void rateLimitsAnonymousRequestsByIp() throws Exception {
        when(clientIpResolver.resolve(any())).thenReturn("198.51.100.20");
        int allowed = 0;
        while (mvc.perform(get("/amiusingavpn")).andReturn().getResponse().getStatus() != 429) {
            allowed++;
            assertThat(allowed).isLessThan(110); // A token may refill while looping
        }
        assertThat(allowed).isGreaterThanOrEqualTo(100);
        mvc.perform(get("/amiusingavpn"))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.status").value(429));
        
        // Other clients are unaffected
        when(clientIpResolver.resolve(any())).thenReturn("198.51.100.21");
        mvc.perform(get("/amiusingavpn")).andExpect(status().isNotFound());
    }
    
    @TestConfiguration
    static class Mocks {
        @Bean
        APIKeyRepository apiKeyRepository() {
            APIKeyRepository repository = mock(APIKeyRepository.class);
            when(repository.count()).thenReturn(1L); // Skip creating the default key
            when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
            return repository;
        }
        
        @Bean
        MetricService metricService() {
            MetricService metrics = mock(MetricService.class);
            when(metrics.getTracker(DatabaseTracker.class)).thenReturn(mock(DatabaseTracker.class));
            when(metrics.getTracker(RequestTracker.class)).thenReturn(mock(RequestTracker.class));
            return metrics;
        }
    }
}
