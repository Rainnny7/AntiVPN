package me.braydon.antivpn.service;

import inet.ipaddr.IPAddress;
import jakarta.annotation.PostConstruct;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.IPUtils;
import me.braydon.antivpn.common.IpRangeIndex;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.model.Allowlist;
import me.braydon.antivpn.model.Blacklist;
import me.braydon.antivpn.repository.AllowlistRepository;
import me.braydon.antivpn.repository.BlacklistRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Operator-managed blacklists and allowlists.
 * <p>
 * Entries are cached in memory and reloaded
 * whenever a list is modified through this service.
 * </p>
 *
 * @author Braydon
 */
@Service
@Slf4j(topic = "Policy Lists")
public class PolicyListService {
    @NonNull private final BlacklistRepository blacklistRepository;
    @NonNull private final AllowlistRepository allowlistRepository;
    
    /**
     * Incremented whenever a list changes.
     */
    @NonNull private final AtomicLong version = new AtomicLong();
    
    @NonNull private volatile Lists lists = new Lists(Set.of(), Set.of(), IpRangeIndex.empty(), Set.of());
    
    public PolicyListService(@NonNull BlacklistRepository blacklistRepository, @NonNull AllowlistRepository allowlistRepository) {
        this.blacklistRepository = blacklistRepository;
        this.allowlistRepository = allowlistRepository;
    }
    
    /**
     * Reload every list from the database.
     */
    @PostConstruct
    public synchronized void reload() {
        Set<String> asnBlacklist = new HashSet<>(), countryBlacklist = new HashSet<>(), allowRanges = new HashSet<>();
        Set<Long> allowAsns = new HashSet<>();
        for (Blacklist blacklist : blacklistRepository.findAll()) {
            for (String entry : blacklist.getEntries()) {
                switch (blacklist.getType()) {
                    case ASN -> parseAsn(entry).ifPresent(asn -> asnBlacklist.add(String.valueOf(asn)));
                    case COUNTRY -> countryBlacklist.add(entry.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        for (Allowlist allowlist : allowlistRepository.findAll()) {
            for (String entry : allowlist.getEntries()) {
                switch (allowlist.getType()) {
                    case IP_RANGE -> allowRanges.add(entry);
                    case ASN -> parseAsn(entry).ifPresent(allowAsns::add);
                }
            }
        }
        lists = new Lists(Set.copyOf(asnBlacklist), Set.copyOf(countryBlacklist), IpRangeIndex.of(allowRanges), Set.copyOf(allowAsns));
        version.incrementAndGet();
        log.info("Loaded {} ASN and {} country blacklist entries, {} range and {} ASN allowlist entries",
            asnBlacklist.size(), countryBlacklist.size(), allowRanges.size(), allowAsns.size());
    }
    
    /**
     * Check if the given address is allowlisted.
     *
     * @param address the address
     * @param asn     the ASN of the address, null if unknown
     * @return true if allowlisted, otherwise false
     */
    public boolean isAllowlisted(@NonNull IPAddress address, Long asn) {
        Lists lists = this.lists;
        return lists.allowRanges().contains(address) || (asn != null && lists.allowAsns().contains(asn));
    }
    
    /**
     * Get the blacklists matching the given ASN and country.
     *
     * @param asn         the ASN, null if unknown
     * @param countryCode the country ISO code, null if unknown
     * @param countryName the country name, null if unknown
     * @return the matching blacklists
     */
    @NonNull
    public Set<Blacklist.BlacklistType> getBlacklists(Long asn, String countryCode, String countryName) {
        Lists lists = this.lists;
        Set<Blacklist.BlacklistType> matched = EnumSet.noneOf(Blacklist.BlacklistType.class);
        if (asn != null && lists.asnBlacklist().contains(String.valueOf(asn))) {
            matched.add(Blacklist.BlacklistType.ASN);
        }
        if ((countryCode != null && lists.countryBlacklist().contains(countryCode.toLowerCase(Locale.ROOT)))
            || (countryName != null && lists.countryBlacklist().contains(countryName.toLowerCase(Locale.ROOT)))) {
            matched.add(Blacklist.BlacklistType.COUNTRY);
        }
        return matched;
    }
    
    /**
     * Add the given entry to a blacklist if it's
     * not on it, otherwise remove it.
     *
     * @param type  the type of blacklist
     * @param entry the entry
     * @return true if the entry was added, false if it was removed
     * @throws APIException if the entry is invalid
     */
    public synchronized boolean toggleBlacklist(@NonNull Blacklist.BlacklistType type, @NonNull String entry) {
        String normalized = switch (type) {
            case ASN -> String.valueOf(parseAsn(entry).orElseThrow(() -> invalid("Invalid ASN: " + entry)));
            case COUNTRY -> requireNotBlank(entry);
        };
        Blacklist blacklist = blacklistRepository.findByType(type);
        if (blacklist == null) {
            blacklist = new Blacklist();
            blacklist.setType(type);
            blacklist.setEntries(new HashSet<>());
        }
        boolean added = toggle(blacklist.getEntries(), normalized);
        blacklistRepository.save(blacklist);
        reload();
        return added;
    }
    
    /**
     * Add the given entry to an allowlist if it's
     * not on it, otherwise remove it.
     *
     * @param type  the type of allowlist
     * @param entry the entry
     * @return true if the entry was added, false if it was removed
     * @throws APIException if the entry is invalid
     */
    public synchronized boolean toggleAllowlist(@NonNull Allowlist.AllowlistType type, @NonNull String entry) {
        String normalized = switch (type) {
            case IP_RANGE -> {
                IPAddress address = IPUtils.parse(entry).orElseThrow(() -> invalid("Invalid IP address or CIDR block: " + entry));
                yield (address.isPrefixed() ? address.toPrefixBlock() : address).toCanonicalString();
            }
            case ASN -> String.valueOf(parseAsn(entry).orElseThrow(() -> invalid("Invalid ASN: " + entry)));
        };
        Allowlist allowlist = allowlistRepository.findByType(type);
        if (allowlist == null) {
            allowlist = new Allowlist();
            allowlist.setType(type);
            allowlist.setEntries(new HashSet<>());
        }
        boolean added = toggle(allowlist.getEntries(), normalized);
        allowlistRepository.save(allowlist);
        reload();
        return added;
    }
    
    /**
     * Get every blacklist.
     *
     * @return the blacklists
     */
    @NonNull
    public List<Blacklist> getAllBlacklists() {
        return blacklistRepository.findAll();
    }
    
    /**
     * Get every allowlist.
     *
     * @return the allowlists
     */
    @NonNull
    public List<Allowlist> getAllAllowlists() {
        return allowlistRepository.findAll();
    }
    
    /**
     * Get the current version of the lists.
     *
     * @return the version
     */
    public long getVersion() {
        return version.get();
    }
    
    /**
     * Parse an ASN, accepting "13335" and "AS13335".
     *
     * @param input the input
     * @return the ASN, empty if invalid
     */
    @NonNull
    public static Optional<Long> parseAsn(@NonNull String input) {
        String trimmed = input.trim();
        if (trimmed.regionMatches(true, 0, "AS", 0, 2)) {
            trimmed = trimmed.substring(2);
        }
        try {
            long asn = Long.parseLong(trimmed);
            return asn > 0L && asn <= 4_294_967_295L ? Optional.of(asn) : Optional.empty();
        } catch (NumberFormatException ex) {
            return Optional.empty();
        }
    }
    
    private static boolean toggle(@NonNull Set<String> entries, @NonNull String entry) {
        if (entries.remove(entry)) {
            return false;
        }
        entries.add(entry);
        return true;
    }
    
    @NonNull
    private static String requireNotBlank(@NonNull String entry) {
        if (entry.isBlank()) {
            throw invalid("Entry cannot be empty");
        }
        return entry.trim();
    }
    
    @NonNull
    private static APIException invalid(@NonNull String message) {
        return new APIException(HttpStatus.BAD_REQUEST, message);
    }
    
    private record Lists(@NonNull Set<String> asnBlacklist, @NonNull Set<String> countryBlacklist,
                         @NonNull IpRangeIndex allowRanges, @NonNull Set<Long> allowAsns) {}
}
