package me.braydon.antivpn.detection;

import inet.ipaddr.IPAddress;
import jakarta.annotation.PostConstruct;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.IpRangeIndex;
import me.braydon.antivpn.common.StringUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Keeps every {@link DetectionSource} up to date,
 * and looks up addresses against their data.
 *
 * @author Braydon
 */
@Service
@Slf4j(topic = "Detection")
public class DetectionService {
    @NonNull private final DetectionProperties properties;
    @NonNull private final SnapshotStore snapshots;
    @NonNull private final HostingAsns hostingAsns;
    @NonNull private final ObjectProvider<TaskScheduler> scheduler;
    
    /**
     * The state of every enabled source, in registration order.
     */
    @NonNull private final Map<String, SourceState> states = new LinkedHashMap<>();
    
    /**
     * Incremented whenever the data used for lookups changes.
     */
    @NonNull private final AtomicLong generation = new AtomicLong();
    
    /**
     * The ids of the sources that were active at the last staleness check.
     */
    @NonNull private volatile Set<String> activeSources = Set.of();
    
    public DetectionService(@NonNull List<DetectionSource> sources, @NonNull DetectionProperties properties,
                            @NonNull SnapshotStore snapshots, @NonNull HostingAsns hostingAsns,
                            @NonNull ObjectProvider<TaskScheduler> scheduler) {
        this.properties = properties;
        this.snapshots = snapshots;
        this.hostingAsns = hostingAsns;
        this.scheduler = scheduler;
        for (DetectionSource source : sources) {
            if (properties.getDisabledSources().contains(source.getId())) {
                log.info("Source {} is disabled", source.getId());
                continue;
            }
            if (states.putIfAbsent(source.getId(), new SourceState(source)) != null) {
                throw new IllegalStateException("Duplicate detection source id: " + source.getId());
            }
        }
    }
    
    @PostConstruct
    public void initialize() {
        Instant now = Instant.now();
        for (SourceState state : states.values()) {
            snapshots.read(state.getSource().getId()).ifPresent(snapshot -> restore(state, snapshot));
        }
        recheckStaleness();
        if (!properties.isSchedulingEnabled()) {
            log.info("Source scheduling is disabled");
            return;
        }
        TaskScheduler taskScheduler = scheduler.getObject();
        int index = 0;
        for (SourceState state : states.values()) {
            DetectionSource source = state.getSource();
            Instant updatedAt = state.getUpdatedAt();
            Instant due = updatedAt == null ? now : updatedAt.plus(source.getRefreshInterval());
            
            // Spread out the initial fetches so we don't hit everything at once
            Instant start = due.isBefore(now) ? now.plusSeconds(2L * index++) : due;
            taskScheduler.scheduleWithFixedDelay(() -> refresh(source.getId()), start, source.getRefreshInterval());
            log.info("Scheduled {} every {}, next refresh at {}", source.getId(), source.getRefreshInterval(), start);
        }
    }
    
    /**
     * Fetch the given source from upstream and apply the result.
     *
     * @param sourceId the id of the source
     * @return true if the source was updated, otherwise false
     */
    public boolean refresh(@NonNull String sourceId) {
        SourceState state = getState(sourceId);
        state.setLastAttemptAt(Instant.now());
        long before = System.currentTimeMillis();
        List<String> entries;
        try {
            entries = state.getSource().fetch();
        } catch (Exception ex) {
            state.setLastError("Fetch failed: " + ex.getMessage());
            log.warn("Failed to fetch {}, keeping the last good data: {}", sourceId, ex.toString());
            return false;
        }
        boolean applied = apply(sourceId, entries, Instant.now());
        if (applied) {
            log.info("Refreshed {} in {}ms", sourceId, System.currentTimeMillis() - before);
        }
        return applied;
    }
    
    /**
     * Apply freshly fetched entries to the given source.
     *
     * @param sourceId the id of the source
     * @param entries  the fetched entries
     * @param now      the current time
     * @return true if the entries were accepted, false if the guard rejected them
     */
    public boolean apply(@NonNull String sourceId, @NonNull List<String> entries, @NonNull Instant now) {
        SourceState state = getState(sourceId);
        DetectionSource source = state.getSource();
        SourceGuard.Result result = SourceGuard.check(entries, state.getLastFetchCount(),
            properties.getMinRetainedRatio(), properties.getMaxUnsafeRatio());
        if (!result.unsafe().isEmpty()) {
            log.warn("Dropped {} unsafe entries from {}, e.g. {}", result.unsafe().size(), sourceId,
                result.unsafe().subList(0, Math.min(5, result.unsafe().size())));
        }
        if (result.isRejected()) {
            state.setLastError("Rejected: " + result.rejection());
            log.warn("Rejected refresh of {}, keeping the last good data: {}", sourceId, result.rejection());
            return false;
        }
        Map<String, Instant> lastSeen = new LinkedHashMap<>();
        Duration retention = source.getRetention();
        if (retention != null) {
            Instant cutoff = now.minus(retention);
            state.getLastSeen().forEach((entry, seen) -> {
                if (seen.isAfter(cutoff)) {
                    lastSeen.put(entry, seen);
                }
            });
        }
        for (IPAddress address : result.accepted()) {
            lastSeen.put(address.toCanonicalString(), now);
        }
        IpRangeIndex index = retention == null ? IpRangeIndex.ofAddresses(result.accepted()) : IpRangeIndex.of(lastSeen.keySet());
        state.setIndex(index);
        state.setLastSeen(retention == null ? Collections.emptyMap() : lastSeen);
        state.setLastFetchCount(result.accepted().size());
        state.setUpdatedAt(now);
        state.setLastError(null);
        generation.incrementAndGet();
        recheckStaleness();
        
        log.info("Loaded {} blocks for {} ({} fetched, {} invalid)", StringUtils.formatNumber(index.size()), sourceId,
            StringUtils.formatNumber(result.accepted().size()), result.invalid());
        try {
            snapshots.write(sourceId, now, result.accepted().size(), lastSeen);
        } catch (Exception ex) {
            log.warn("Failed to write snapshot for {}: {}", sourceId, ex.toString());
        }
        return true;
    }
    
    /**
     * Look up the given address against every active source.
     *
     * @param address the address
     * @param asn     the ASN of the address, null if unknown
     * @return the detections, in source registration order
     */
    @NonNull
    public List<Detection> lookup(@NonNull IPAddress address, Long asn) {
        List<Detection> detections = new ArrayList<>();
        Instant now = Instant.now();
        for (SourceState state : states.values()) {
            if (isStale(state, now)) {
                continue;
            }
            DetectionSource source = state.getSource();
            state.getIndex().find(address).ifPresent(range -> detections.add(
                new Detection(source.getId(), source.getName(), source.getCategory(), source.getConfidence(), range)
            ));
        }
        if (asn != null) {
            hostingAsns.get(asn).ifPresent(name -> detections.add(
                new Detection("hosting-asn", name, Category.HOSTING, Confidence.LIKELY, "AS" + asn)
            ));
        }
        return detections;
    }
    
    /**
     * Check if the given source has fresh enough data to be used for lookups.
     *
     * @param state the source state
     * @param now   the current time
     * @return true if stale, otherwise false
     */
    public boolean isStale(@NonNull SourceState state, @NonNull Instant now) {
        Instant updatedAt = state.getUpdatedAt();
        if (updatedAt == null) {
            return true;
        }
        Duration interval = state.getSource().getRefreshInterval();
        Duration staleAfter = Duration.ofMillis((long) (interval.toMillis() * properties.getStaleAfterMultiplier()));
        if (staleAfter.compareTo(properties.getMinStaleAfter()) < 0) {
            staleAfter = properties.getMinStaleAfter();
        }
        return updatedAt.plus(staleAfter).isBefore(now);
    }
    
    /**
     * Bump the generation when a source becomes stale or fresh,
     * so cached lookups made with the old data are recomputed.
     */
    @Scheduled(fixedDelay = 60_000L, initialDelay = 60_000L)
    public void recheckStaleness() {
        Instant now = Instant.now();
        Set<String> active = new HashSet<>();
        for (SourceState state : states.values()) {
            if (!isStale(state, now)) {
                active.add(state.getSource().getId());
            }
        }
        if (!active.equals(activeSources)) {
            Set<String> stale = new TreeSet<>(states.keySet());
            stale.removeAll(active);
            if (!stale.isEmpty()) {
                log.warn("Sources without fresh data (ignored for lookups): {}", stale);
            }
            activeSources = Set.copyOf(active);
            generation.incrementAndGet();
        }
    }
    
    /**
     * Get the current generation of the lookup data.
     *
     * @return the generation
     */
    public long getGeneration() {
        return generation.get();
    }
    
    /**
     * Get the state of every enabled source.
     *
     * @return the states
     */
    @NonNull
    public Collection<SourceState> getStates() {
        return Collections.unmodifiableCollection(states.values());
    }
    
    /**
     * Get the state of the given source.
     *
     * @param sourceId the id of the source
     * @return the state, empty if the source isn't enabled
     */
    @NonNull
    public Optional<SourceState> findState(@NonNull String sourceId) {
        return Optional.ofNullable(states.get(sourceId));
    }
    
    @NonNull
    private SourceState getState(@NonNull String sourceId) {
        return findState(sourceId).orElseThrow(() -> new IllegalArgumentException("Unknown source: " + sourceId));
    }
    
    private void restore(@NonNull SourceState state, @NonNull SnapshotStore.Snapshot snapshot) {
        DetectionSource source = state.getSource();
        state.setIndex(IpRangeIndex.of(snapshot.entries().keySet()));
        state.setLastSeen(source.getRetention() == null ? Collections.emptyMap() : new LinkedHashMap<>(snapshot.entries()));
        state.setLastFetchCount(snapshot.fetchCount());
        state.setUpdatedAt(snapshot.updatedAt());
        generation.incrementAndGet();
        log.info("Restored {} blocks for {} from snapshot (updated {})",
            StringUtils.formatNumber(state.getIndex().size()), source.getId(), snapshot.updatedAt());
    }
}
