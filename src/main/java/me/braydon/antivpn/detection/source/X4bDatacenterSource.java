package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * X4BNet's list of datacenter networks.
 *
 * @author Braydon
 * @see <a href="https://github.com/X4BNet/lists_vpn">X4BNet/lists_vpn</a>
 */
@Component
public final class X4bDatacenterSource extends PlainListSource {
    public X4bDatacenterSource() {
        super("x4b-datacenter", "X4BNet datacenter list", Category.HOSTING, Confidence.LIKELY, Duration.ofHours(24L),
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt"
        );
    }
}
