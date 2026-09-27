package me.braydon.antivpn.detection;

import lombok.NonNull;
import me.braydon.antivpn.model.Blacklist;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Turns the detections for an address into a verdict.
 * <p>
 * Rules that keep ordinary users from being flagged:
 * <ul>
 *     <li>Only VPN sources set {@code vpn}, hosting, abuse, relay and blacklists never do.</li>
 *     <li>iCloud Private Relay matches suppress hosting and likely-VPN matches, since the
 *     relay egresses from Akamai, Cloudflare and Fastly networks.</li>
 *     <li>Allowlisted addresses are always clean.</li>
 *     <li>The risk is the strongest single signal, weaker signals don't stack.</li>
 * </ul>
 * </p>
 *
 * @author Braydon
 */
@Component
public final class DetectionEngine {
    @NonNull private final DetectionProperties.Weights weights;
    
    @Autowired
    public DetectionEngine(@NonNull DetectionProperties properties) {
        this(properties.getWeights());
    }
    
    public DetectionEngine(@NonNull DetectionProperties.Weights weights) {
        this.weights = weights;
    }
    
    /**
     * Evaluate the given detections.
     *
     * @param detections  the detections for the address
     * @param allowlisted whether the address is allowlisted
     * @param blacklists  the operator blacklists the address is on
     * @return the verdict
     */
    @NonNull
    public Verdict evaluate(@NonNull List<Detection> detections, boolean allowlisted, @NonNull Set<Blacklist.BlacklistType> blacklists) {
        if (allowlisted) {
            return Verdict.clean(true);
        }
        boolean relay = detections.stream().anyMatch(detection -> detection.category() == Category.RELAY);
        List<Detection> kept = new ArrayList<>();
        for (Detection detection : detections) {
            if (relay && isSuppressedByRelay(detection)) {
                continue;
            }
            kept.add(detection);
        }
        float risk = 0F;
        String provider = null;
        EnumSet<Category> categories = EnumSet.noneOf(Category.class);
        for (Detection detection : kept) {
            categories.add(detection.category());
            risk = Math.max(risk, weight(detection));
            if (provider == null && detection.category() == Category.VPN && detection.confidence() == Confidence.CONFIRMED) {
                provider = detection.name();
            }
        }
        if (blacklists.contains(Blacklist.BlacklistType.ASN)) {
            risk += weights.getAsnBlacklist();
        }
        if (blacklists.contains(Blacklist.BlacklistType.COUNTRY)) {
            risk += weights.getCountryBlacklist();
        }
        risk = Math.round(Math.min(risk, 1F) * 100F) / 100F;
        return new Verdict(
            risk,
            categories.contains(Category.VPN),
            provider != null,
            provider,
            categories.contains(Category.TOR),
            categories.contains(Category.RELAY),
            categories.contains(Category.HOSTING),
            categories.contains(Category.ABUSE),
            false,
            blacklists.isEmpty() ? Set.of() : Collections.unmodifiableSet(EnumSet.copyOf(blacklists)),
            List.copyOf(kept)
        );
    }
    
    private static boolean isSuppressedByRelay(@NonNull Detection detection) {
        return detection.category() == Category.HOSTING
               || (detection.category() == Category.VPN && detection.confidence() == Confidence.LIKELY);
    }
    
    private float weight(@NonNull Detection detection) {
        return switch (detection.category()) {
            case VPN -> detection.confidence() == Confidence.CONFIRMED ? weights.getVpnConfirmed() : weights.getVpnLikely();
            case TOR -> weights.getTor();
            case ABUSE -> weights.getAbuse();
            case HOSTING -> weights.getHosting();
            case RELAY -> weights.getRelay();
        };
    }
    
    /**
     * The verdict for an address.
     *
     * @param risk        the risk score, between 0 and 1
     * @param vpn         whether the address is a VPN server
     * @param vpnProvider whether a VPN provider's own server list matched
     * @param provider    the name of that VPN provider, null if none
     * @param tor         whether the address is a Tor exit node
     * @param relay       whether the address is a consumer privacy relay
     * @param hosting     whether the address is a datacenter or hosting network
     * @param abuse       whether the address is on an abuse list
     * @param allowlisted whether the address is allowlisted
     * @param blacklists  the operator blacklists the address is on
     * @param detections  the detections that counted towards the verdict
     */
    public record Verdict(float risk, boolean vpn, boolean vpnProvider, String provider, boolean tor, boolean relay,
                          boolean hosting, boolean abuse, boolean allowlisted,
                          @NonNull Set<Blacklist.BlacklistType> blacklists, @NonNull List<Detection> detections) {
        @NonNull
        static Verdict clean(boolean allowlisted) {
            return new Verdict(0F, false, false, null, false, false, false, false, allowlisted, Set.of(), List.of());
        }
    }
}
