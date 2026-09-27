package me.braydon.antivpn.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Downloads, refreshes and reads the MaxMind GeoLite2 databases.
 *
 * @author Braydon
 */
@Service
@Slf4j(topic = "Maxmind")
public class MaxmindService {
    private static final String DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz";
    private static final String LEGACY_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz";
    
    /**
     * MaxMind updates GeoLite2 twice a week.
     */
    private static final Duration MAX_AGE = Duration.ofDays(7L);
    
    /**
     * Redirects are followed by hand so the credentials
     * aren't sent on to the storage host.
     */
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                                                      .followRedirects(HttpClient.Redirect.NEVER)
                                                      .connectTimeout(Duration.ofSeconds(10L))
                                                      .build();
    
    /**
     * The MaxMind account id.
     */
    @Value("${maxmind.account-id:}")
    private String accountId;
    
    /**
     * The license key to use for Maxmind.
     */
    @Value("${maxmind.license:}")
    private String license;
    
    /**
     * The directory the databases are stored in.
     */
    @Value("${maxmind.directory:maxmind}")
    private File directory;
    
    @NonNull private final Map<MaxmindDatabase, AtomicReference<DatabaseReader>> readers = new EnumMap<>(MaxmindDatabase.class);
    
    public MaxmindService() {
        for (MaxmindDatabase database : MaxmindDatabase.values()) {
            readers.put(database, new AtomicReference<>());
        }
    }
    
    /**
     * Initialize this component.
     */
    @PostConstruct
    public void initialize() {
        if (!directory.exists() && !directory.mkdirs()) {
            log.warn("Could not create the database directory '{}'", directory);
        }
        log.info("Storing databases in the '{}' directory", directory); // Log the database dir
        if (!canDownload()) {
            log.warn("No MaxMind license key configured, using existing databases only");
        }
        for (MaxmindDatabase database : MaxmindDatabase.values()) {
            File file = getFile(database);
            if (canDownload() && isOutdated(file)) {
                download(database);
            }
            load(database);
        }
    }
    
    /**
     * Refresh any outdated databases.
     */
    @Scheduled(fixedDelay = 6L, initialDelay = 6L, timeUnit = TimeUnit.HOURS)
    public void refresh() {
        if (!canDownload()) {
            return;
        }
        for (MaxmindDatabase database : MaxmindDatabase.values()) {
            if (isOutdated(getFile(database)) && download(database)) {
                load(database);
            }
        }
    }
    
    @PreDestroy
    public void destroy() {
        for (AtomicReference<DatabaseReader> reader : readers.values()) {
            close(reader.getAndSet(null));
        }
    }
    
    /**
     * Look up the ASN of the given address.
     *
     * @param address the address
     * @return the ASN response, empty if unknown or the database isn't loaded
     */
    @NonNull
    public Optional<AsnResponse> asn(@NonNull InetAddress address) {
        DatabaseReader reader = readers.get(MaxmindDatabase.ASN).get();
        if (reader == null) {
            return Optional.empty();
        }
        try {
            return reader.tryAsn(address);
        } catch (Exception ex) {
            log.warn("ASN lookup failed for {}: {}", address.getHostAddress(), ex.toString());
            return Optional.empty();
        }
    }
    
    /**
     * Look up the location of the given address.
     *
     * @param address the address
     * @return the city response, empty if unknown or the database isn't loaded
     */
    @NonNull
    public Optional<CityResponse> city(@NonNull InetAddress address) {
        DatabaseReader reader = readers.get(MaxmindDatabase.CITY).get();
        if (reader == null) {
            return Optional.empty();
        }
        try {
            return reader.tryCity(address);
        } catch (Exception ex) {
            log.warn("City lookup failed for {}: {}", address.getHostAddress(), ex.toString());
            return Optional.empty();
        }
    }
    
    /**
     * Check if the given database is loaded.
     *
     * @param database the database
     * @return true if loaded, otherwise false
     */
    public boolean isLoaded(@NonNull MaxmindDatabase database) {
        return readers.get(database).get() != null;
    }
    
    private boolean canDownload() {
        return license != null && !license.isBlank();
    }
    
    @NonNull
    private File getFile(@NonNull MaxmindDatabase database) {
        return new File(directory, database.getId() + ".mmdb");
    }
    
    private static boolean isOutdated(@NonNull File file) {
        return !file.exists() || Instant.ofEpochMilli(file.lastModified()).plus(MAX_AGE).isBefore(Instant.now());
    }
    
    private void load(@NonNull MaxmindDatabase database) {
        File file = getFile(database);
        if (!file.exists()) {
            log.warn("Database '{}' is missing, {} lookups are unavailable", file, database);
            return;
        }
        try {
            DatabaseReader previous = readers.get(database).getAndSet(new DatabaseReader.Builder(file).build());
            if (previous != null) {
                // Give in-flight lookups on the old reader time to finish
                CompletableFuture.delayedExecutor(1L, TimeUnit.MINUTES).execute(() -> close(previous));
            }
            log.info("Loaded database '{}'", file);
        } catch (IOException ex) {
            log.error("Failed loading database '{}'", file, ex);
        }
    }
    
    /**
     * Download the given database, replacing the local copy.
     *
     * @param database the database
     * @return true if downloaded, otherwise false
     */
    private boolean download(@NonNull MaxmindDatabase database) {
        String id = database.getId();
        Path tempDir = null;
        try {
            log.info("Downloading database {}...", id);
            tempDir = Files.createTempDirectory("maxmind-");
            Path tarFile = tempDir.resolve(id + ".tar.gz");
            try (InputStream inputStream = openDownload(id)) {
                Files.copy(inputStream, tarFile, StandardCopyOption.REPLACE_EXISTING);
            }
            FileUtils.extract(tarFile.toFile(), tempDir.toFile(), ".mmdb");
            Path extracted = tempDir.resolve(id + ".mmdb");
            if (!Files.exists(extracted)) {
                throw new IOException("Archive did not contain " + id + ".mmdb");
            }
            Files.move(extracted, getFile(database).toPath(), StandardCopyOption.REPLACE_EXISTING);
            log.info("Successfully downloaded database '{}'", id);
            return true;
        } catch (Exception ex) {
            log.error("Failed to download database '{}': {}", id, ex.toString());
            return false;
        } finally {
            if (tempDir != null) {
                org.apache.commons.io.FileUtils.deleteQuietly(tempDir.toFile());
            }
        }
    }
    
    @NonNull
    private InputStream openDownload(@NonNull String id) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder().timeout(Duration.ofMinutes(5L));
        if (accountId == null || accountId.isBlank()) {
            log.warn("No maxmind.account-id configured, falling back to the legacy download endpoint");
            request.uri(URI.create(String.format(LEGACY_DOWNLOAD_URL, id, license)));
        } else {
            String credentials = Base64.getEncoder().encodeToString((accountId + ":" + license).getBytes(StandardCharsets.UTF_8));
            request.uri(URI.create(String.format(DOWNLOAD_URL, id))).header("Authorization", "Basic " + credentials);
        }
        HttpResponse<InputStream> response = HTTP_CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        int status = response.statusCode();
        if (status >= 300 && status < 400) {
            response.body().close();
            String location = response.headers().firstValue("Location")
                                  .orElseThrow(() -> new IOException("Redirect without a location"));
            response = HTTP_CLIENT.send(HttpRequest.newBuilder(URI.create(location)).timeout(Duration.ofMinutes(5L)).build(),
                HttpResponse.BodyHandlers.ofInputStream());
            status = response.statusCode();
        }
        if (status != 200) {
            response.body().close();
            throw new IOException("Bad status code (" + status + ") returned");
        }
        return response.body();
    }
    
    private static void close(DatabaseReader reader) {
        if (reader == null) {
            return;
        }
        try {
            reader.close();
        } catch (IOException ignored) {
        }
    }
    
    @RequiredArgsConstructor @Getter
    public enum MaxmindDatabase {
        CITY("GeoLite2-City"),
        ASN("GeoLite2-ASN");
        
        /**
         * The id of this database.
         */
        @NonNull private final String id;
    }
}
