package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.utils.IOUtils;

import java.io.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Braydon
 */
@UtilityClass
public final class FileUtils {
    /**
     * Extract a tar file.
     *
     * @param tarFile     the tar file
     * @param destination the destination directory to extract to
     * @param extensions  the optional extensions to extract
     * @throws IOException if an error occurs while extracting
     * @see File for file and destination
     */
    public static void extract(@NonNull File tarFile, @NonNull File destination, @NonNull String... extensions) throws IOException {
        if (destination.isFile()) { // Destination is not a directory
            throw new IllegalArgumentException("Destination must be a directory");
        }
        Set<String> extensionsSet = extensions.length < 1 ? null : new HashSet<>(Arrays.asList(extensions)); // The set of extensions
        
        try (FileInputStream fileInputStream = new FileInputStream(tarFile);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
             GzipCompressorInputStream gzipCompressorInputStream = new GzipCompressorInputStream(bufferedInputStream);
             TarArchiveInputStream tarArchiveInputStream = new TarArchiveInputStream(gzipCompressorInputStream)
        ) {
            TarArchiveEntry entry; // The current entry
            while ((entry = tarArchiveInputStream.getNextTarEntry()) != null) { // Iterate over the entries
                if (!entry.isFile()) { // Ignore directories
                    continue;
                }
                String fileName = entry.getName(); // The name of the file
                fileName = fileName.substring(fileName.lastIndexOf("/") + 1); // Remove the path
                if (!fileName.contains(".")) { // Doesn't have an extension
                    continue;
                }
                String extension = fileName.split("\\.")[1].toLowerCase(); // The extension of the file
                if (extensionsSet == null || (extensionsSet.contains("." + extension))) { // Get all or specific files
                    File outputFile = new File(destination, fileName); // The output file
                    try (OutputStream outputFileStream = new FileOutputStream(outputFile)) {
                        IOUtils.copy(tarArchiveInputStream, outputFileStream); // Copy the file to the output
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
