package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

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
    public static final String ADDRESS_REGEX = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$";
    
    /**
     * Get the real IP from the given request.
     *
     * @param request the request
     * @return the real IP
     */
    @NonNull
    public static String getRealIp(@NonNull HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        String cfAddress = request.getHeader("CF-Connecting-IP");
        if (cfAddress != null) { // Use the CloudFlare ip if present in the request
            ip = cfAddress;
        }
        return ip;
    }
    
    /**
     * Check if the given input is
     * a valid IPv4 address.
     *
     * @param input the input
     * @return true if IPv4, otherwise false
     */
    public static boolean isIpV4(@NonNull String input) {
        return input.matches(ADDRESS_REGEX);
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
