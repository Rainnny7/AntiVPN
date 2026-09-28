package me.braydon.antivpn.common;

import me.braydon.antivpn.exception.impl.APIException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LookupMetadataTest {
    @Test
    void readsDottedQueryParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("ip", "1.2.3.4");
        request.setParameter("metadata.player", "Steve");
        request.setParameter("metadata.uuid", "abc-123");
        
        assertThat(LookupMetadata.fromRequest(request))
            .containsExactly(Map.entry("player", "Steve"), Map.entry("uuid", "abc-123"));
    }
    
    @Test
    void readsBracketQueryParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("metadata[player]", "Steve");
        
        assertThat(LookupMetadata.fromRequest(request)).containsEntry("player", "Steve");
    }
    
    @Test
    void readsJsonQueryParameter() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("metadata", "{\"player\":\"Steve\",\"kills\":12}");
        
        assertThat(LookupMetadata.fromRequest(request))
            .containsEntry("player", "Steve")
            .containsEntry("kills", "12");
    }
    
    @Test
    void dottedParametersOverrideJson() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("metadata", "{\"player\":\"Alex\"}");
        request.setParameter("metadata.player", "Steve");
        
        assertThat(LookupMetadata.fromRequest(request)).containsEntry("player", "Steve");
    }
    
    @Test
    void rejectsInvalidJson() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("metadata", "{nope");
        
        assertThatThrownBy(() -> LookupMetadata.fromRequest(request))
            .isInstanceOf(APIException.class)
            .hasMessage("Invalid metadata JSON");
    }
    
    @Test
    void rejectsNonObjectJson() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("metadata", "[\"Steve\"]");
        
        assertThatThrownBy(() -> LookupMetadata.fromRequest(request))
            .isInstanceOf(APIException.class)
            .hasMessage("Metadata must be a JSON object");
    }
    
    @Test
    void sanitizesAMapFromAJsonBody() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("player", "Steve");
        raw.put("online", true);
        raw.put("skip", null);
        raw.put("", "empty");
        
        assertThat(LookupMetadata.fromMap(raw)).containsExactly(Map.entry("player", "Steve"), Map.entry("online", "true"));
    }
    
    @Test
    void truncatesAndCapsEntries() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("k".repeat(LookupMetadata.MAX_KEY_LENGTH + 5), "v".repeat(LookupMetadata.MAX_VALUE_LENGTH + 5));
        for (int i = 0; i < LookupMetadata.MAX_ENTRIES + 5; i++) {
            raw.put("k" + i, "v" + i);
        }
        
        Map<String, String> metadata = LookupMetadata.fromMap(raw);
        assertThat(metadata).hasSize(LookupMetadata.MAX_ENTRIES);
        assertThat(metadata.keySet().iterator().next()).hasSize(LookupMetadata.MAX_KEY_LENGTH);
        assertThat(metadata.values().iterator().next()).hasSize(LookupMetadata.MAX_VALUE_LENGTH);
    }
    
    @Test
    void emptyAndNullMapsAreEmpty() {
        assertThat(LookupMetadata.fromMap(null)).isEmpty();
        assertThat(LookupMetadata.fromMap(Map.of())).isEmpty();
        assertThat(LookupMetadata.fromRequest(new MockHttpServletRequest())).isEmpty();
    }
}
