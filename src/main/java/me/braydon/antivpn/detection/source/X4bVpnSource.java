package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * X4BNet's list of networks used by VPN providers.
 * <p>
 * Derived from the ASNs VPN providers host on, so it
 * can include other servers on the same networks.
 * </p>
 *
 * @author Braydon
 * @see <a href="https://github.com/X4BNet/lists_vpn">X4BNet/lists_vpn</a>
 */
@Component
public final class X4bVpnSource extends PlainListSource {
    public X4bVpnSource() {
        super("x4b-vpn", "X4BNet VPN list", Category.VPN, Confidence.LIKELY, Duration.ofHours(24L),
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"
        );
    }
}
