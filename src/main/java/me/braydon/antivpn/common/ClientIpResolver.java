package me.braydon.antivpn.common;

import inet.ipaddr.IPAddress;
import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import me.braydon.antivpn.detection.DetectionProperties;
import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.detection.SourceState;
import me.braydon.antivpn.detection.source.CloudflareSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Works out the real client IP of a request.
 * <p>
 * Forwarding headers can be set by anyone, so they're only
 * honored when the connection comes from a trusted proxy:
 * {@code X-Forwarded-For} from {@link DetectionProperties#getTrustedProxies()},
 * and {@code CF-Connecting-IP} from Cloudflare's published ranges
 * when {@link DetectionProperties#isTrustCloudflare()} is enabled.
 * </p>
 *
 * @author Braydon
 */
@Component
public class ClientIpResolver {
    @NonNull private final IpRangeIndex trustedProxies;
    private final boolean trustCloudflare;
    @NonNull private final Supplier<IpRangeIndex> cloudflareRanges;
    
    @Autowired
    public ClientIpResolver(@NonNull DetectionProperties properties, @NonNull ObjectProvider<DetectionService> detectionService) {
        this(properties.getTrustedProxies(), properties.isTrustCloudflare(), () -> {
            DetectionService service = detectionService.getIfAvailable();
            return service == null ? IpRangeIndex.empty()
                       : service.findState(CloudflareSource.ID).map(SourceState::getIndex).orElse(IpRangeIndex.empty());
        });
    }
    
    public ClientIpResolver(@NonNull List<String> trustedProxies, boolean trustCloudflare, @NonNull Supplier<IpRangeIndex> cloudflareRanges) {
        this.trustedProxies = IpRangeIndex.of(trustedProxies);
        this.trustCloudflare = trustCloudflare;
        this.cloudflareRanges = cloudflareRanges;
    }
    
    /**
     * Get the real client IP of the given request.
     *
     * @param request the request
     * @return the client IP
     */
    @NonNull
    public String resolve(@NonNull HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        Optional<IPAddress> remote = IPUtils.parseAddress(remoteAddr);
        if (remote.isEmpty()) {
            return remoteAddr;
        }
        if (trustCloudflare && cloudflareRanges.get().contains(remote.get())) {
            Optional<IPAddress> connecting = IPUtils.parseAddress(request.getHeader("CF-Connecting-IP"));
            if (connecting.isPresent()) {
                return connecting.get().toCanonicalString();
            }
        }
        if (trustedProxies.contains(remote.get())) {
            String forwardedFor = request.getHeader("X-Forwarded-For");
            if (forwardedFor != null) {
                // Walk from the closest hop back, the first untrusted hop is the client
                String[] hops = forwardedFor.split(",");
                for (int i = hops.length - 1; i >= 0; i--) {
                    Optional<IPAddress> hop = IPUtils.parseAddress(hops[i]);
                    if (hop.isEmpty()) {
                        break;
                    }
                    if (!trustedProxies.contains(hop.get())) {
                        return hop.get().toCanonicalString();
                    }
                }
            }
        }
        return remote.get().toCanonicalString();
    }
}
