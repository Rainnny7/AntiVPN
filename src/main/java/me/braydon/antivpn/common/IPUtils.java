package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import javax.servlet.http.HttpServletRequest;
import java.util.function.Consumer;

/**
 * @author Braydon
 */
@UtilityClass
public final class IPUtils {
    /**
     * The regex expression for validating IPv4 addresses.
     */
    public static final String IPV4_REGEX = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$";
    
    /**
     * The regex expression for validating IPv6 addresses.
     */
    public static final String IPV6_REGEX = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$";
    
    private static final String[] IP_HEADERS = new String[] {
        "CF-Connecting-IP",
        "X-Forwarded-For"
    };
    
    /**
     * Get the real IP from the given request.
     *
     * @param request the request
     * @return the real IP
     */
    @NonNull
    public static String getRealIp(@NonNull HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        for (String headerName : IP_HEADERS) {
            String header = request.getHeader(headerName);
            if (header == null) {
                continue;
            }
            if (!header.contains(",")) { // Handle single IP
                ip = header;
                break;
            }
            // Handle multiple IPs
            String[] ips = header.split(",");
            for (String ipHeader : ips) {
                ip = ipHeader;
                break;
            }
        }
        return ip;
    }
    
    /**
     * Get the IP type of the given input.
     *
     * @param input the input
     * @return the IP type
     */
    public static int getIpType(@NonNull String input) {
        return isIpV4(input) ? 4 : isIpV6(input) ? 6 : -1;
    }
    
    /**
     * Check if the given input is
     * a valid IPv4 address.
     *
     * @param input the input
     * @return true if IPv4, otherwise false
     */
    public static boolean isIpV4(@NonNull String input) {
        return input.matches(IPV4_REGEX);
    }
    
    /**
     * Check if the given input is
     * a valid IPv6 address.
     *
     * @param input the input
     * @return true if IPv6, otherwise false
     */
    public static boolean isIpV6(@NonNull String input) {
        return input.matches(IPV6_REGEX);
    }
    
    /**
     * Get the IP from the given hostname
     * by looking up the DNS records.
     *
     * @param hostname the hostname
     * @param callback the callback which supplies the ip
     */
    @SneakyThrows
    public static void getIpFromHostname(@NonNull String hostname, @NonNull Consumer<String> callback) {
        try {
            Lookup lookup = new Lookup(hostname, Type.A); // Get all A records for the hostname
            lookup.setResolver(new SimpleResolver("1.1.1.1")); // Use Cloudflare's DNS
            Record[] records = lookup.run(); // Run the lookup
            if (records == null) { // Error when retrieving DNS records
                throw new NullPointerException("DNS A records are null for " + hostname);
            }
            for (Record record : records) {
                String value = record.rdataToString(); // The value of the record
                callback.accept(value); // Run the callback
            }
        } catch (TextParseException ex) {
            ex.printStackTrace();
        }
    }
}
