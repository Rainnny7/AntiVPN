package me.braydon.antivpn.blacklist;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Set;

/**
 * Represents a blacklist.
 *
 * @author Braydon
 */
@Document("blacklists")
@AllArgsConstructor
@Getter
@ToString
public final class Blacklist {
    /**
     * The type of this blacklist.
     *
     * @see BlacklistType for type
     */
    @Id @NonNull private final BlacklistType type;
    
    /**
     * The entries in this blacklist.
     */
    @NonNull private final Set<Object> entries;
    
    /**
     * Add an entry to this blacklist.
     *
     * @param entry the entry to add
     */
    public void addEntry(@NonNull Object entry) {
        entries.add(entry);
    }
    
    /**
     * Check if this blacklist contains an entry.
     *
     * @param entry the entry to check
     * @return true if true, otherwise false
     */
    public boolean containsEntry(@NonNull Object entry) {
        return entries.contains(entry);
    }
    
    /**
     * Remove an entry from this blacklist.
     *
     * @param entry the entry to remove
     */
    public void removeEntry(@NonNull Object entry) {
        entries.remove(entry);
    }
}
