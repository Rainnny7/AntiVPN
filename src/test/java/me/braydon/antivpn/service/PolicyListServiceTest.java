package me.braydon.antivpn.service;

import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.model.Allowlist;
import me.braydon.antivpn.model.Blacklist;
import me.braydon.antivpn.repository.AllowlistRepository;
import me.braydon.antivpn.repository.BlacklistRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PolicyListServiceTest {
    private final List<Blacklist> blacklists = new ArrayList<>();
    private final List<Allowlist> allowlists = new ArrayList<>();
    private PolicyListService service;
    
    @BeforeEach
    void setUp() {
        BlacklistRepository blacklistRepository = mock(BlacklistRepository.class);
        when(blacklistRepository.findAll()).thenAnswer(invocation -> List.copyOf(blacklists));
        when(blacklistRepository.findByType(any())).thenAnswer(invocation -> blacklists.stream()
            .filter(blacklist -> blacklist.getType() == invocation.getArgument(0)).findFirst().orElse(null));
        when(blacklistRepository.save(any())).thenAnswer(invocation -> {
            Blacklist blacklist = invocation.getArgument(0);
            if (!blacklists.contains(blacklist)) {
                blacklists.add(blacklist);
            }
            return blacklist;
        });
        
        AllowlistRepository allowlistRepository = mock(AllowlistRepository.class);
        when(allowlistRepository.findAll()).thenAnswer(invocation -> List.copyOf(allowlists));
        when(allowlistRepository.findByType(any())).thenAnswer(invocation -> allowlists.stream()
            .filter(allowlist -> allowlist.getType() == invocation.getArgument(0)).findFirst().orElse(null));
        when(allowlistRepository.save(any())).thenAnswer(invocation -> {
            Allowlist allowlist = invocation.getArgument(0);
            if (!allowlists.contains(allowlist)) {
                allowlists.add(allowlist);
            }
            return allowlist;
        });
        
        service = new PolicyListService(blacklistRepository, allowlistRepository);
        service.reload();
    }
    
    @Test
    void parsesAsns() {
        assertThat(PolicyListService.parseAsn("13335")).contains(13335L);
        assertThat(PolicyListService.parseAsn(" AS13335 ")).contains(13335L);
        assertThat(PolicyListService.parseAsn("as4294967295")).contains(4_294_967_295L);
        assertThat(PolicyListService.parseAsn("0")).isEmpty();
        assertThat(PolicyListService.parseAsn("4294967296")).isEmpty();
        assertThat(PolicyListService.parseAsn("-5")).isEmpty();
        assertThat(PolicyListService.parseAsn("AS")).isEmpty();
        assertThat(PolicyListService.parseAsn("cloudflare")).isEmpty();
    }
    
    @Test
    void togglesAsnBlacklist() {
        assertThat(service.toggleBlacklist(Blacklist.BlacklistType.ASN, "AS14061")).isTrue();
        assertThat(service.getBlacklists(14061L, null, null)).containsExactly(Blacklist.BlacklistType.ASN);
        
        assertThat(service.toggleBlacklist(Blacklist.BlacklistType.ASN, "14061")).isFalse();
        assertThat(service.getBlacklists(14061L, null, null)).isEmpty();
    }
    
    @Test
    void matchesCountriesByCodeOrName() {
        service.toggleBlacklist(Blacklist.BlacklistType.COUNTRY, "GB");
        service.toggleBlacklist(Blacklist.BlacklistType.COUNTRY, "Sweden");
        
        assertThat(service.getBlacklists(null, "gb", "United Kingdom")).containsExactly(Blacklist.BlacklistType.COUNTRY);
        assertThat(service.getBlacklists(null, "SE", "sweden")).containsExactly(Blacklist.BlacklistType.COUNTRY);
        assertThat(service.getBlacklists(null, "US", "United States")).isEmpty();
        assertThat(service.getBlacklists(null, null, null)).isEmpty();
    }
    
    @Test
    void rejectsInvalidEntries() {
        assertThatThrownBy(() -> service.toggleBlacklist(Blacklist.BlacklistType.ASN, "nope")).isInstanceOf(APIException.class);
        assertThatThrownBy(() -> service.toggleBlacklist(Blacklist.BlacklistType.COUNTRY, " ")).isInstanceOf(APIException.class);
        assertThatThrownBy(() -> service.toggleAllowlist(Allowlist.AllowlistType.IP_RANGE, "999.0.0.0/8")).isInstanceOf(APIException.class);
        assertThatThrownBy(() -> service.toggleAllowlist(Allowlist.AllowlistType.ASN, "AS0")).isInstanceOf(APIException.class);
    }
    
    @Test
    void allowlistsRangesAndAsns() {
        service.toggleAllowlist(Allowlist.AllowlistType.IP_RANGE, "89.35.28.0/24");
        service.toggleAllowlist(Allowlist.AllowlistType.ASN, "AS1221");
        
        assertThat(service.isAllowlisted(IPUtils.parseAddress("89.35.28.131").orElseThrow(), null)).isTrue();
        assertThat(service.isAllowlisted(IPUtils.parseAddress("89.35.29.1").orElseThrow(), null)).isFalse();
        assertThat(service.isAllowlisted(IPUtils.parseAddress("1.128.0.1").orElseThrow(), 1221L)).isTrue();
        assertThat(allowlists.getFirst().getEntries()).contains("89.35.28.0/24");
    }
    
    @Test
    void normalizesAllowlistedRanges() {
        service.toggleAllowlist(Allowlist.AllowlistType.IP_RANGE, "89.35.28.77/24");
        
        assertThat(allowlists.getFirst().getEntries()).containsExactly("89.35.28.0/24");
    }
    
    @Test
    void bumpsTheVersionOnChanges() {
        long before = service.getVersion();
        
        service.toggleBlacklist(Blacklist.BlacklistType.COUNTRY, "GB");
        
        assertThat(service.getVersion()).isGreaterThan(before);
    }
}
