package me.braydon.antivpn.cache;

import me.braydon.antivpn.service.AddressService.LookupData;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CachedAddressDataTest {
    private static CachedAddressData cached(Set<LookupData> lookupData) {
        return new CachedAddressData("1.128.0.1", lookupData, "{}", 0L, "1:1");
    }
    
    @Test
    void entriesWithoutLookupDataCoverPlainLookups() {
        // Redis returns null for an empty set
        assertThat(cached(null).covers(Set.of())).isTrue();
        assertThat(cached(null).covers(Set.of(LookupData.ASN))).isFalse();
    }
    
    @Test
    void entriesCoverTheirOwnLookupData() {
        CachedAddressData cached = cached(Set.of(LookupData.ASN));
        
        assertThat(cached.covers(Set.of())).isTrue();
        assertThat(cached.covers(Set.of(LookupData.ASN))).isTrue();
        assertThat(cached.covers(Set.of(LookupData.ASN, LookupData.GEOGRAPHICAL))).isFalse();
    }
}
