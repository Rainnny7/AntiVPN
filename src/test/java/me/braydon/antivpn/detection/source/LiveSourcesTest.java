package me.braydon.antivpn.detection.source;

import me.braydon.antivpn.detection.DetectionSource;
import me.braydon.antivpn.detection.SourceGuard;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fetches every source from upstream to catch format changes.
 * <p>
 * Excluded from the normal build, run with {@code mvn test -Plive}.
 * </p>
 */
@Tag("live")
class LiveSourcesTest {
    static Stream<Arguments> sources() {
        return Stream.of(
            Arguments.of(new NordVpnSource(), 1000),
            Arguments.of(new PiaSource(), 100),
            Arguments.of(new MullvadSource(), 300),
            Arguments.of(new SurfsharkSource(), 50),
            Arguments.of(new TorSource(), 500),
            Arguments.of(new SpamhausDropSource(), 500),
            Arguments.of(new X4bVpnSource(), 1000),
            Arguments.of(new X4bDatacenterSource(), 1000),
            Arguments.of(new AwsSource(), 1000),
            Arguments.of(new GcpSource(), 100),
            Arguments.of(new CloudflareSource(), 10),
            Arguments.of(new ICloudPrivateRelaySource(), 10000)
        );
    }
    
    @ParameterizedTest(name = "{0}")
    @MethodSource("sources")
    void fetchesUsableData(DetectionSource source, int minimumEntries) throws Exception {
        List<String> entries = source.fetch();
        SourceGuard.Result result = SourceGuard.check(entries, 0, 0.5, 0.01);
        
        assertThat(result.rejection()).isNull();
        assertThat(result.accepted()).hasSizeGreaterThanOrEqualTo(minimumEntries);
        assertThat(result.invalid()).isLessThanOrEqualTo(entries.size() / 100);
    }
}
