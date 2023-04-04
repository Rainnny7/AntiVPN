package me.braydon.antivpn.service;

import com.maxmind.geoip2.DatabaseReader;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "Maxmind")
public class MaxmindService {
    /**
     * The license key to use for Maxmind.
     */
    @Value("${maxmind.license}")
    private String license;
    
    /**
     * Initialize this component.
     */
    @PostConstruct
    public void initialize() {
        if (license.trim().isEmpty()) { // We need a license
            throw new IllegalStateException("You must provide a license key for Maxmind");
        }
        File databasesDir = new File("maxmind"); // The directory to store the databases in
        if (!databasesDir.exists()) { // Create the directory if it doesn't exist
            databasesDir.mkdirs();
        }
        log.info("Storing databases in the '{}' directory", databasesDir); // Log the database dir
        
        for (MaxmindDatabase database : MaxmindDatabase.values()) {
            String databaseId = database.getId(); // The id of the database
            File localFile = new File(databasesDir, databaseId + ".mmdb"); // The local database file
            File tarFile = new File(databasesDir, databaseId + ".tar.gz"); // The tar file of the downloaded database
            
            // Download the database files if they don't exist, or we have an old download to extract
            if (!localFile.exists() || tarFile.exists()) {
                // Download the tar file for the database if we don't have one
                if (!tarFile.exists()) {
                    String downloadUrl = String.format("https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz",
                        databaseId, // The database to download
                        license // The licence key for auth
                    ); // The url of the database to download
                    
                    log.info("Downloading database {}...", databaseId); // Log the download
                    try { // Attempt to download
                        FileUtils.copyURLToFile(new URL(downloadUrl), tarFile);
                    } catch (IOException ex) { // Failed to download
                        log.error("Failed to download database '{}'", databaseId, ex);
                        continue;
                    }
                }
                // Extract the database we downloaded
                log.info("Extracting downloaded database file '{}'...", tarFile); // Log the unzip
                try { // Attempt to extract
                    me.braydon.antivpn.common.FileUtils.extract(tarFile, databasesDir, ".mmdb");
                    tarFile.delete(); // Delete the tar file after we extract it
                } catch (IOException ex) {
                    log.error("Failed to extract database '{}'", tarFile, ex);
                    continue;
                }
                
                // Log the successful download of the database
                log.info("Successfully downloaded database '{}'", databaseId);
            } else { // Log that we found a database
                log.info("Found database '{}'", databaseId);
            }
            try { // Attempt to load the database reaer
                database.setDatabaseReader(new DatabaseReader.Builder(localFile).build());
                log.info("Successfully loaded database reader for '{}'", localFile);
            } catch (IOException ex) {
                log.error("Failed loading database reader for '{}'", localFile, ex);
            }
        }
    }
    
    @RequiredArgsConstructor @Getter @ToString(onlyExplicitlyIncluded = true)
    public enum MaxmindDatabase {
        CITY("GeoLite2-City"),
        ASN("GeoLite2-ASN");
        
        /**
         * The id of this database.
         */
        @NonNull private final String id;
        
        /**
         * The reader for this database.
         *
         * @see DatabaseReader for reader
         */
        @Setter(AccessLevel.PROTECTED) private DatabaseReader databaseReader;
    }
}
