package me.braydon.antivpn.detection;

import me.braydon.antivpn.model.Blacklist;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionEngineTest {
    private static final Detection NORD = new Detection("nordvpn", "NordVPN", Category.VPN, Confidence.CONFIRMED, "89.35.28.131");
    private static final Detection X4B_VPN = new Detection("x4b-vpn", "X4BNet VPN list", Category.VPN, Confidence.LIKELY, "2.26.157.0/24");
    private static final Detection TOR = new Detection("tor", "Tor", Category.TOR, Confidence.CONFIRMED, "171.25.193.25");
    private static final Detection DROP = new Detection("spamhaus-drop", "Spamhaus DROP", Category.ABUSE, Confidence.CONFIRMED, "1.10.16.0/20");
    private static final Detection DATACENTER = new Detection("x4b-datacenter", "X4BNet datacenter list", Category.HOSTING, Confidence.LIKELY, "104.28.0.0/16");
    private static final Detection HOSTING_ASN = new Detection("hosting-asn", "DigitalOcean", Category.HOSTING, Confidence.LIKELY, "AS14061");
    private static final Detection RELAY = new Detection("icloud-private-relay", "iCloud Private Relay", Category.RELAY, Confidence.CONFIRMED, "104.28.0.0/24");
    
    private final DetectionEngine engine = new DetectionEngine(new DetectionProperties.Weights());
    
    @Test
    void residentialAddressIsClean() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(), false, Set.of());
        
        assertThat(verdict.risk()).isZero();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.tor()).isFalse();
        assertThat(verdict.hosting()).isFalse();
        assertThat(verdict.relay()).isFalse();
        assertThat(verdict.abuse()).isFalse();
        assertThat(verdict.detections()).isEmpty();
    }
    
    @Test
    void confirmedVpnProviderIsFlagged() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(NORD, HOSTING_ASN), false, Set.of());
        
        assertThat(verdict.vpn()).isTrue();
        assertThat(verdict.vpnProvider()).isTrue();
        assertThat(verdict.provider()).isEqualTo("NordVPN");
        assertThat(verdict.hosting()).isTrue();
        assertThat(verdict.risk()).isEqualTo(1F);
    }
    
    @Test
    void likelyVpnIsFlaggedWithoutAProvider() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(X4B_VPN), false, Set.of());
        
        assertThat(verdict.vpn()).isTrue();
        assertThat(verdict.vpnProvider()).isFalse();
        assertThat(verdict.provider()).isNull();
        assertThat(verdict.risk()).isEqualTo(0.75F);
    }
    
    @Test
    void torIsNotAVpn() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(TOR), false, Set.of());
        
        assertThat(verdict.tor()).isTrue();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.risk()).isEqualTo(1F);
    }
    
    @Test
    void hostingAloneIsNotAVpn() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(DATACENTER, HOSTING_ASN), false, Set.of());
        
        assertThat(verdict.hosting()).isTrue();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.risk()).isEqualTo(0.5F); // signals don't stack
    }
    
    @Test
    void abuseIsNotAVpn() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(DROP), false, Set.of());
        
        assertThat(verdict.abuse()).isTrue();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.risk()).isEqualTo(0.9F);
    }
    
    @Test
    void privateRelaySuppressesHostingAndLikelyVpnMatches() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(RELAY, DATACENTER, HOSTING_ASN, X4B_VPN), false, Set.of());
        
        assertThat(verdict.relay()).isTrue();
        assertThat(verdict.hosting()).isFalse();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.risk()).isEqualTo(0.1F);
        assertThat(verdict.detections()).containsExactly(RELAY);
    }
    
    @Test
    void privateRelayDoesNotHideConfirmedVpns() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(RELAY, NORD), false, Set.of());
        
        assertThat(verdict.vpn()).isTrue();
        assertThat(verdict.risk()).isEqualTo(1F);
    }
    
    @Test
    void blacklistedCountryRaisesRiskButIsNotAVpn() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(), false, Set.of(Blacklist.BlacklistType.COUNTRY));
        
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.blacklists()).containsExactly(Blacklist.BlacklistType.COUNTRY);
        assertThat(verdict.risk()).isEqualTo(0.4F);
    }
    
    @Test
    void blacklistsStackOnTopOfDetectionsUpToOne() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(HOSTING_ASN), false,
            Set.of(Blacklist.BlacklistType.ASN, Blacklist.BlacklistType.COUNTRY));
        
        assertThat(verdict.risk()).isEqualTo(1F);
        assertThat(verdict.vpn()).isFalse();
    }
    
    @Test
    void allowlistWinsOverEverything() {
        DetectionEngine.Verdict verdict = engine.evaluate(List.of(NORD, TOR, DROP), true, Set.of(Blacklist.BlacklistType.ASN));
        
        assertThat(verdict.allowlisted()).isTrue();
        assertThat(verdict.risk()).isZero();
        assertThat(verdict.vpn()).isFalse();
        assertThat(verdict.tor()).isFalse();
        assertThat(verdict.abuse()).isFalse();
        assertThat(verdict.blacklists()).isEmpty();
        assertThat(verdict.detections()).isEmpty();
    }
    
    @Test
    void usesConfiguredWeights() {
        DetectionProperties.Weights weights = new DetectionProperties.Weights();
        weights.setHosting(0.2F);
        
        assertThat(new DetectionEngine(weights).evaluate(List.of(HOSTING_ASN), false, Set.of()).risk()).isEqualTo(0.2F);
    }
}
