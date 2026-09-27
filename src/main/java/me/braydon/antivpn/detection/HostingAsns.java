package me.braydon.antivpn.detection;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * The ASNs of networks that only host servers.
 * <p>
 * Loaded from the bundled {@code hosting-asns.txt}, plus any
 * {@link DetectionProperties#getExtraHostingAsns()}.
 * </p>
 *
 * @author Braydon
 */
@Component
@Slf4j(topic = "Hosting ASNs")
public class HostingAsns {
    private static final String RESOURCE = "hosting-asns.txt";
    
    /**
     * The hosting ASNs mapped to the name of their network.
     */
    @NonNull private final Map<Long, String> asns;
    
    @Autowired
    public HostingAsns(@NonNull DetectionProperties properties) throws IOException {
        Map<Long, String> asns = new HashMap<>(load());
        for (Long extra : properties.getExtraHostingAsns()) {
            asns.putIfAbsent(extra, "Configured hosting ASN");
        }
        this.asns = Collections.unmodifiableMap(asns);
        log.info("Loaded {} hosting ASNs", this.asns.size());
    }
    
    HostingAsns(@NonNull Map<Long, String> asns) {
        this.asns = Map.copyOf(asns);
    }
    
    /**
     * Get the network name of the given ASN if it's a hosting ASN.
     *
     * @param asn the ASN
     * @return the network name, empty if not a hosting ASN
     */
    @NonNull
    public Optional<String> get(long asn) {
        return Optional.ofNullable(asns.get(asn));
    }
    
    /**
     * Parse the bundled list.
     * <p>
     * Each line is {@code <asn> # <name>}, blank lines
     * and lines starting with {@code #} are ignored.
     * </p>
     */
    @NonNull
    static Map<Long, String> load() throws IOException {
        Map<Long, String> asns = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
            new ClassPathResource(RESOURCE).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int comment = line.indexOf('#');
                String asn = (comment < 0 ? line : line.substring(0, comment)).trim();
                String name = comment < 0 ? "AS" + asn : line.substring(comment + 1).trim();
                asns.put(Long.parseLong(asn.toUpperCase(Locale.ROOT).replace("AS", "")), name);
            }
        }
        return asns;
    }
}
