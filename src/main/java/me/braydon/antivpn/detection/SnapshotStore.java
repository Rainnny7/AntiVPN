package me.braydon.antivpn.detection;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Stores the last good copy of each source on disk,
 * so detection works immediately after a restart.
 * <p>
 * Format: a few {@code # key=value} header lines, then one
 * entry per line, optionally followed by a tab and the
 * epoch millis of when the entry was last seen.
 * </p>
 *
 * @author Braydon
 */
@Component
@Slf4j(topic = "Snapshots")
public class SnapshotStore {
    @NonNull private final Path directory;
    
    public SnapshotStore(@NonNull DetectionProperties properties) {
        directory = properties.getSnapshotDirectory();
    }
    
    /**
     * Write a snapshot for the given source.
     *
     * @param sourceId   the id of the source
     * @param updatedAt  when the source was refreshed
     * @param fetchCount the amount of entries accepted from the fetch
     * @param entries    the entries mapped to when they were last seen
     * @throws IOException if writing fails
     */
    public void write(@NonNull String sourceId, @NonNull Instant updatedAt, int fetchCount,
                      @NonNull Map<String, Instant> entries) throws IOException {
        Files.createDirectories(directory);
        Path target = file(sourceId);
        Path temp = directory.resolve(sourceId + ".txt.tmp");
        try (BufferedWriter writer = Files.newBufferedWriter(temp, StandardCharsets.UTF_8)) {
            writer.write("# source=" + sourceId + "\n");
            writer.write("# updated=" + updatedAt.toEpochMilli() + "\n");
            writer.write("# fetched=" + fetchCount + "\n");
            for (Map.Entry<String, Instant> entry : entries.entrySet()) {
                writer.write(entry.getKey());
                writer.write('\t');
                writer.write(Long.toString(entry.getValue().toEpochMilli()));
                writer.write('\n');
            }
        }
        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    
    /**
     * Read the snapshot for the given source.
     *
     * @param sourceId the id of the source
     * @return the snapshot, empty if there is none or it can't be read
     */
    @NonNull
    public Optional<Snapshot> read(@NonNull String sourceId) {
        Path file = file(sourceId);
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        Instant updatedAt = null;
        int fetchCount = 0;
        Map<String, Instant> entries = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                if (line.startsWith("# updated=")) {
                    updatedAt = Instant.ofEpochMilli(Long.parseLong(line.substring(10).trim()));
                } else if (line.startsWith("# fetched=")) {
                    fetchCount = Integer.parseInt(line.substring(10).trim());
                } else if (!line.startsWith("#")) {
                    int tab = line.indexOf('\t');
                    if (tab < 0) {
                        entries.put(line.trim(), updatedAt);
                    } else {
                        entries.put(line.substring(0, tab), Instant.ofEpochMilli(Long.parseLong(line.substring(tab + 1).trim())));
                    }
                }
            }
        } catch (IOException | RuntimeException ex) {
            log.warn("Ignoring unreadable snapshot {}: {}", file, ex.getMessage());
            return Optional.empty();
        }
        if (updatedAt == null) {
            log.warn("Ignoring snapshot {} without an updated timestamp", file);
            return Optional.empty();
        }
        return Optional.of(new Snapshot(updatedAt, fetchCount, entries));
    }
    
    @NonNull
    private Path file(@NonNull String sourceId) {
        return directory.resolve(sourceId + ".txt");
    }
    
    /**
     * A stored snapshot.
     *
     * @param updatedAt  when the source was refreshed
     * @param fetchCount the amount of entries accepted from the fetch
     * @param entries    the entries mapped to when they were last seen
     */
    public record Snapshot(@NonNull Instant updatedAt, int fetchCount, @NonNull Map<String, Instant> entries) {}
}
