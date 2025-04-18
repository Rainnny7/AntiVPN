package me.braydon.antivpn.repository;

import lombok.NonNull;
import me.braydon.antivpn.model.Blacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * The {@link Blacklist.BlacklistType} repository.
 *
 * @author Braydon
 */
@Repository
public interface BlacklistRepository extends JpaRepository<Blacklist, Long> {
    /**
     * Find the blacklist with the given type.
     *
     * @param type the type of blacklist
     * @return the blacklist, null if none
     * @see Blacklist.BlacklistType for type
     */
    @Query("SELECT a FROM Blacklist a WHERE a.type = :type")
    Blacklist findByType(@NonNull Blacklist.BlacklistType type);
    
    /**
     * Check if the blacklist with the given type contains the given entry.
     *
     * @param type  the type of blacklist
     * @param entry the entry to check
     * @return true if the blacklist with the given type contains the given entry, false otherwise
     * @see Blacklist.BlacklistType for type
     */
    default boolean contains(@NonNull Blacklist.BlacklistType type, @NonNull String entry) {
        Blacklist blacklist = findByType(type);
        if (blacklist != null) {
            return blacklist.getEntries().contains(entry);
        }
        return false;
    }
}