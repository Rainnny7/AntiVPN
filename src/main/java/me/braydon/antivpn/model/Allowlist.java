package me.braydon.antivpn.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

import java.util.Set;

/**
 * Represents an allowlist.
 * <p>
 * Addresses matching an allowlist are always
 * reported as clean, regardless of detections.
 * </p>
 *
 * @author Braydon
 */
@Entity
@Table(name = "allowlists")
@Setter
@Getter
@ToString
public class Allowlist {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    /**
     * The type of this allowlist.
     *
     * @see AllowlistType for type
     */
    @NonNull
    @Enumerated(EnumType.STRING)
    private AllowlistType type;
    
    /**
     * The entries in this allowlist.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "allowlist_entries")
    @Column(name = "allowlist_entry")
    @NonNull
    private Set<String> entries;
    
    /**
     * The type of allowlists.
     *
     * @author Braydon
     */
    public enum AllowlistType {
        /**
         * An allowlist for IP addresses and CIDR blocks.
         */
        IP_RANGE,
        
        /**
         * An allowlist for ASN numbers.
         */
        ASN
    }
}
