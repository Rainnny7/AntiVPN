package me.braydon.antivpn.model;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import java.util.Set;

/**
 * Represents a blacklist.
 *
 * @author Braydon
 */
@Entity
@Table(name = "blacklists")
@Setter
@Getter
@ToString
public class Blacklist {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @NonNull
    private Long id;
    
    /**
     * The type of this blacklist.
     *
     * @see BlacklistType for type
     */
    @NonNull private BlacklistType type;
    
    /**
     * The entries in this blacklist.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "blacklist_entries")
    @Column(name = "blacklist_entry")
    @NonNull
    private Set<String> entries;
    
    /**
     * Add an entry to this blacklist.
     *
     * @param entry the entry to add
     */
    public void addEntry(@NonNull String entry) {
        entries.add(entry);
    }
    
    /**
     * Check if this blacklist contains an entry.
     *
     * @param entry the entry to check
     * @return true if true, otherwise false
     */
    public boolean containsEntry(@NonNull String entry) {
        return entries.contains(entry);
    }
    
    /**
     * Remove an entry from this blacklist.
     *
     * @param entry the entry to remove
     */
    public void removeEntry(@NonNull String entry) {
        entries.remove(entry);
    }
    
    /**
     * The type of blacklists.
     *
     * @author Braydon
     */
    public enum BlacklistType {
        /**
         * A blacklist for ASN numbers and organizations.
         */
        ASN,
        
        /**
         * A blacklist for countries.
         */
        COUNTRY
    }
}
