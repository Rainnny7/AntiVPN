package me.braydon.antivpn.service;

import com.maxmind.geoip2.DatabaseReader;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author Braydon
 */
@Service
@Slf4j(topic = "Maxmind")
public class MaxmindService {
    @Getter private static MaxmindService instance;
    
    /**
     * The license key to use for Maxmind.
     */
    @Value("${maxmind.license}")
    private String license;
    
    /**
     * The list of databases to download.
     */
    @Value("${maxmind.databases}")
    private String[] databases;
    
    /**
     * The loaded database readers.
     *
     * @see DatabaseReader for reader
     */
    @Getter private final Set<DatabaseReader> databaseReaders = Collections.synchronizedSet(new HashSet<>());
    
    /**
     * Initialize this component.
     */
    @PostConstruct
    public void initialize() {
        instance = this; // Set the instance
        
        if (license.trim().isEmpty()) { // We need a license
            throw new IllegalStateException("You must provide a license key for Maxmind");
        }
        File databasesDir = new File("maxmind"); // The directory to store the databases in
        if (!databasesDir.exists()) { // Create the directory if it doesn't exist
            databasesDir.mkdirs();
        }
        log.info("Storing databases in the '{}' directory", databasesDir); // Log the database dir
        
        for (String database : databases) {
            File localFile = new File(databasesDir, database + ".mmdb"); // The local database file
            File tarFile = new File(databasesDir, database + ".tar.gz"); // The tar file of the downloaded database
            // todo: make outdated local files update to
            if (!localFile.exists() || tarFile.exists()) { // We don't have the file, or we have a new version
                // Download the tar file for the database if we don't have one
                if (!tarFile.exists()) {
                    String downloadUrl = String.format("https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz",
                        database, // The database to download
                        license // The licence key for auth
                    ); // The url of the database to download
                    
                    log.info("Downloading database {}...", database); // Log the download
                    try { // Attempt to download
                        FileUtils.copyURLToFile(new URL(downloadUrl), tarFile);
                    } catch (IOException ex) { // Failed to download
                        log.error("Failed to download database '{}'", database, ex);
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
                log.info("Successfully downloaded database '{}'", database);
            } else {
                // Log that we found a database
                log.info("Found database '{}'", database);
            }
            try { // Attemot to load the database reaer
                databaseReaders.add(new DatabaseReader.Builder(localFile).build());
            } catch (IOException ex) {
                log.error("Failed loading database reader for '{}'", localFile, ex);
            }
        }
    }
    
    /**
     * Submit a task to be executed on a database reader.
     *
     * @param callback the task
     * @see Consumer for task
     * @see DatabaseReader for database reader
     */
    public void submitTask(@NonNull Consumer<DatabaseReader> callback) {
        Consumer<Consumer<DatabaseReader>> maxmindTask = consumer -> {
            for (DatabaseReader databaseReader : databaseReaders) {
                try {
                    consumer.accept(databaseReader);
                    break;
                } catch (Exception ignored) {
                    // Failed on the current reader, try another
                }
            }
        };
        maxmindTask.accept(callback);
    }
}
