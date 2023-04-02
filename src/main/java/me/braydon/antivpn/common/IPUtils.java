package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.util.function.Consumer;

/**
 * @author Braydon
 */
@UtilityClass
public final class IPUtils {
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
