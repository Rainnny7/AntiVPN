package me.braydon.antivpn.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

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
     * The type of blacklists.
     *
     * @author Braydon
     */
    public enum BlacklistType {
        /**
         * A blacklist for ASN numbers.
         */
        ASN,
        
        /**
         * A blacklist for countries, by ISO code or name.
         */
        COUNTRY
    }
}
