package me.braydon.antivpn.repository.blacklist;

import lombok.NonNull;
import me.braydon.antivpn.model.Blacklist;

/**
 * The custom repository for {@link Blacklist}'s.
 *
 * @author Braydon
 */
public interface CustomBlacklistRepository {
    /**
     * Check if the blacklist with the given
     * type contains any of the given entries.
     *
     * @param type    the type of blacklist
     * @param entries the entries to check
     * @return true if true, otherwise false
     * @see BlacklistType for type
     */
    boolean contains(@NonNull BlacklistType type, @NonNull Object... entries);
}
