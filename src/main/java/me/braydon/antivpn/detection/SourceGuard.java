package me.braydon.antivpn.detection;

import inet.ipaddr.IPAddress;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.common.IPUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Sanity checks applied to every refresh before it can replace a source's data.
 *
 * @author Braydon
 */
@UtilityClass
public final class SourceGuard {
    /**
     * The broadest IPv4 prefix a source may contain.
     */
    public static final int MIN_IPV4_PREFIX = 8;
    
    /**
     * The broadest IPv6 prefix a source may contain.
     */
    public static final int MIN_IPV6_PREFIX = 24;
    
    /**
     * Check the given entries.
     * <p>
     * Invalid entries are skipped. Unsafe entries (too broad, or overlapping
     * private/reserved space) are dropped, and if there are too many of them
     * the whole refresh is rejected. A refresh that shrinks too much compared
     * to the previous one is rejected, as that usually means a partial or
     * error response rather than a real change.
     * </p>
     *
     * @param entries          the fetched entries
     * @param previousCount    the accepted entry count of the previous refresh, 0 if none
     * @param minRetainedRatio the minimum fraction of the previous count to accept
     * @param maxUnsafeRatio   the maximum fraction of unsafe entries to accept
     * @return the result
     */
    @NonNull
    public static Result check(@NonNull List<String> entries, int previousCount, double minRetainedRatio, double maxUnsafeRatio) {
        List<IPAddress> accepted = new ArrayList<>(entries.size());
        List<String> unsafe = new ArrayList<>();
        int invalid = 0;
        for (String entry : entries) {
            Optional<IPAddress> parsed = IPUtils.parse(entry);
            if (parsed.isEmpty()) {
                invalid++;
                continue;
            }
            IPAddress address = parsed.get();
            if (isUnsafe(address)) {
                unsafe.add(address.toCanonicalString());
                continue;
            }
            accepted.add(address);
        }
        String rejection = null;
        int considered = accepted.size() + unsafe.size();
        if (accepted.isEmpty()) {
            rejection = "No valid entries (" + invalid + " invalid, " + unsafe.size() + " unsafe)";
        } else if ((double) unsafe.size() / considered > maxUnsafeRatio) {
            rejection = String.format("%s of %s entries are too broad or overlap reserved space", unsafe.size(), considered);
        } else if (previousCount > 0 && accepted.size() < previousCount * minRetainedRatio) {
            rejection = String.format("Only %s entries, down from %s", accepted.size(), previousCount);
        }
        return new Result(accepted, invalid, unsafe, rejection);
    }
    
    /**
     * Check if the given address or block is too broad, or overlaps private/reserved space.
     *
     * @param address the address or block
     * @return true if unsafe, otherwise false
     */
    public static boolean isUnsafe(@NonNull IPAddress address) {
        Integer prefix = address.getNetworkPrefixLength();
        if (prefix != null && prefix < (address.isIPv4() ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX)) {
            return true;
        }
        return IPUtils.isReserved(address);
    }
    
    /**
     * The result of a check.
     *
     * @param accepted  the entries that passed
     * @param invalid   the amount of entries that could not be parsed
     * @param unsafe    the entries that were dropped as unsafe
     * @param rejection why the whole refresh was rejected, null if it wasn't
     */
    public record Result(@NonNull List<IPAddress> accepted, int invalid, @NonNull List<String> unsafe, String rejection) {
        public boolean isRejected() {
            return rejection != null;
        }
    }
}
