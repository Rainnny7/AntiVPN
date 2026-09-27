package me.braydon.antivpn.common;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {
    private static final IpRangeIndex CLOUDFLARE = IpRangeIndex.of(List.of("173.245.48.0/20"));
    
    private static MockHttpServletRequest request(String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        return request;
    }
    
    @Test
    void ignoresForwardedForFromUntrustedClients() {
        ClientIpResolver resolver = new ClientIpResolver(List.of(), false, IpRangeIndex::empty);
        MockHttpServletRequest request = request("203.0.113.10");
        request.addHeader("X-Forwarded-For", "1.2.3.4");
        request.addHeader("CF-Connecting-IP", "5.6.7.8");
        
        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.10");
    }
    
    @Test
    void honorsForwardedForFromTrustedProxies() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"), false, IpRangeIndex::empty);
        MockHttpServletRequest request = request("10.0.0.2");
        request.addHeader("X-Forwarded-For", "1.2.3.4");
        
        assertThat(resolver.resolve(request)).isEqualTo("1.2.3.4");
    }
    
    @Test
    void takesTheFirstUntrustedHopFromTheRight() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"), false, IpRangeIndex::empty);
        MockHttpServletRequest request = request("10.0.0.2");
        // A client can prepend anything, only the hops added by our proxies can be trusted
        request.addHeader("X-Forwarded-For", "6.6.6.6, 1.2.3.4, 10.0.0.9");
        
        assertThat(resolver.resolve(request)).isEqualTo("1.2.3.4");
    }
    
    @Test
    void fallsBackToTheRemoteAddressOnGarbage() {
        ClientIpResolver resolver = new ClientIpResolver(List.of("10.0.0.0/8"), false, IpRangeIndex::empty);
        MockHttpServletRequest request = request("10.0.0.2");
        request.addHeader("X-Forwarded-For", "not-an-ip");
        
        assertThat(resolver.resolve(request)).isEqualTo("10.0.0.2");
    }
    
    @Test
    void honorsCloudflareHeaderOnlyFromCloudflare() {
        ClientIpResolver resolver = new ClientIpResolver(List.of(), true, () -> CLOUDFLARE);
        
        MockHttpServletRequest fromCloudflare = request("173.245.48.1");
        fromCloudflare.addHeader("CF-Connecting-IP", "5.6.7.8");
        assertThat(resolver.resolve(fromCloudflare)).isEqualTo("5.6.7.8");
        
        MockHttpServletRequest spoofed = request("203.0.113.10");
        spoofed.addHeader("CF-Connecting-IP", "5.6.7.8");
        assertThat(resolver.resolve(spoofed)).isEqualTo("203.0.113.10");
    }
    
    @Test
    void ignoresCloudflareHeaderWhenDisabled() {
        ClientIpResolver resolver = new ClientIpResolver(List.of(), false, () -> CLOUDFLARE);
        MockHttpServletRequest request = request("173.245.48.1");
        request.addHeader("CF-Connecting-IP", "5.6.7.8");
        
        assertThat(resolver.resolve(request)).isEqualTo("173.245.48.1");
    }
}
