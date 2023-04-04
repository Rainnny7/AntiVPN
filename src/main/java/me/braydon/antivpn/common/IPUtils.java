package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import javax.servlet.http.HttpServletRequest;
import java.util.function.Consumer;

/**
 * @author Braydon
 */
@UtilityClass @Slf4j(topic = "IP Utils")
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
        log.debug("Remote IP: {}", ip); // Debugging
        for (String headerName : IP_HEADERS) {
            String header = request.getHeader(headerName);
            if (header == null) {
                continue;
            }
            log.debug("{} = {}", headerName, header); // Debugging
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
        log.debug("Remote IP: {}", ip); // Debugging
        return ip;
    }
    
    /**
     * Get the IP type of the given input.
     *
     * @param input the input
     * @return the IP type
     */
    @NonNull
    public static String getIpType(@NonNull String input) {
        return isIpV4(input) ? "IPv4" : isIpV6(input) ? "IPv6" : "Unknown";
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
     * Get the IP target of
     * the given DNS server.
     *
     * @param dns      the dns
     * @param callback the callback which supplies the target
     */
    public static void getIpFromDns(@NonNull String dns, @NonNull Consumer<String> callback) {
        Record[] records;
        try {
            Lookup lookup = new Lookup(dns, Type.A);
            records = lookup.run();
            if (records == null) { // Error when retrieving DNS records
                throw new NullPointerException(String.format("Could not retrieve DNS records for '%s'", dns));
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
