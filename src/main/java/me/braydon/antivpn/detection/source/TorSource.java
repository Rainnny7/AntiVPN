package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Tor exit nodes, published by the Tor Project.
 *
 * @author Braydon
 */
@Component
public final class TorSource extends PlainListSource {
    public TorSource() {
        super("tor", "Tor", Category.TOR, Confidence.CONFIRMED, Duration.ofHours(1L),
            "https://check.torproject.org/torbulkexitlist"
        );
    }
}
