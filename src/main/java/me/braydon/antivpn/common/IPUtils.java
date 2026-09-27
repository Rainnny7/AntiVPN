package me.braydon.antivpn.common;

import inet.ipaddr.AddressStringParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @author Braydon
 */
@UtilityClass
public final class IPUtils {
    /**
     * Only accept the standard notations, the library defaults also accept
     * inet_aton shorthand (1.2.3 = 1.2.0.3), wildcards and ranges.
     * <p>
     * Must be initialized before {@link #RESERVED}, which is parsed with it.
     * </p>
     */
    private static final IPAddressStringParameters PARSE_PARAMETERS = new IPAddressStringParameters.Builder()
        .allowEmpty(false)
        .allowAll(false)
        .allowSingleSegment(false)
        .allowPrefixOnly(false)
        .allowWildcardedSeparator(false)
        .allow_inet_aton(false)
        .setRangeOptions(AddressStringParameters.RangeParameters.NO_RANGE)
        .toParams();
    
    /**
     * Special-purpose ranges that never belong to a real client.
     */
    private static final IpRangeIndex RESERVED = IpRangeIndex.of(List.of(
        // IPv4
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        
        // IPv6
        "::/128",
        "::1/128",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8"
    ));
    
    /**
     * The DNS resolver to use for provider hostname lookups.
     */
    private static final Resolver RESOLVER = createResolver();
    
    /**
     * Parse the given input as an IP address, or a CIDR block.
     * <p>
     * IPv4-mapped IPv6 addresses (e.g. ::ffff:1.2.3.4)
     * are normalized to their IPv4 form.
     * </p>
     *
     * @param input the input
     * @return the parsed address, empty if invalid
     */
    @NonNull
    public static Optional<IPAddress> parse(String input) {
        if (input == null) {
            return Optional.empty();
        }
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return Optional.empty();
        }
        IPAddress address = new IPAddressString(trimmed, PARSE_PARAMETERS).getAddress();
        if (address == null) {
            return Optional.empty();
        }
        if (address.isIPv6() && address.toIPv6().isIPv4Mapped()) {
            address = address.toIPv6().getEmbeddedIPv4Address();
        }
        return Optional.of(address);
    }
    
    /**
     * Parse the given input as a single IP address (no prefix length).
     *
     * @param input the input
     * @return the parsed address, empty if invalid or a CIDR block
     */
    @NonNull
    public static Optional<IPAddress> parseAddress(String input) {
        return parse(input).filter(address -> !address.isPrefixed() && !address.isMultiple());
    }
    
    /**
     * Get the IP type of the given input.
     *
     * @param input the input
     * @return 4 or 6, or -1 if the input is not an IP address
     */
    public static int getIpType(@NonNull String input) {
        return parseAddress(input).map(IPUtils::getIpType).orElse(-1);
    }
    
    /**
     * Get the IP type of the given address.
     *
     * @param address the address
     * @return 4 or 6
     */
    public static int getIpType(@NonNull IPAddress address) {
        return address.isIPv4() ? 4 : 6;
    }
    
    /**
     * Check if the given address or block is in
     * (or overlaps) a private or reserved range.
     *
     * @param address the address or block
     * @return true if reserved, otherwise false
     */
    public static boolean isReserved(@NonNull IPAddress address) {
        return RESERVED.overlaps(address);
    }
    
    /**
     * Resolve the A and AAAA records of the given hostname.
     *
     * @param hostname the hostname
     * @return the resolved addresses
     * @throws UnknownHostException if the hostname has no records
     */
    @NonNull
    public static List<String> resolveHostname(@NonNull String hostname) throws UnknownHostException {
        List<String> addresses = new ArrayList<>();
        try {
            for (int type : new int[] { Type.A, Type.AAAA }) {
                Lookup lookup = new Lookup(hostname, type);
                lookup.setResolver(RESOLVER);
                lookup.setCache(null);
                Record[] records = lookup.run();
                if (records == null) {
                    continue;
                }
                for (Record record : records) {
                    if (record instanceof ARecord aRecord) {
                        addresses.add(aRecord.getAddress().getHostAddress());
                    } else if (record instanceof AAAARecord aaaaRecord) {
                        addresses.add(aaaaRecord.getAddress().getHostAddress());
                    }
                }
            }
        } catch (TextParseException ex) {
            throw new UnknownHostException("Invalid hostname: " + hostname);
        }
        if (addresses.isEmpty()) {
            throw new UnknownHostException("No A or AAAA records for " + hostname);
        }
        return addresses;
    }
    
    @NonNull
    private static Resolver createResolver() {
        try {
            SimpleResolver resolver = new SimpleResolver("1.1.1.1"); // Use Cloudflare's DNS
            resolver.setTimeout(Duration.ofSeconds(5L));
            return resolver;
        } catch (UnknownHostException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
