package me.braydon.antivpn.common;

import lombok.NonNull;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;

/**
 * @author Braydon
 */
public final class MemoryFormatter {
    /**
     * Format the bytes to a human-readable format.
     *
     * @param bytes the bytes to format
     * @return the formatted bytes
     */
    @NonNull
    public static String format(long bytes) {
        if (-1000 < bytes && bytes < 1000) { // If the bytes are less than 1000
            return bytes + " B";
        }
        CharacterIterator character = new StringCharacterIterator("kMGTPE");
        while (bytes <= -999_950 || bytes >= 999_950) {
            bytes /= 1000;
            character.next();
        }
        return String.format("%.1f %cB", bytes / 1000.0, character.current());
    }
}