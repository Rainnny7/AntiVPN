package me.braydon.antivpn.repository;

import lombok.NonNull;
import me.braydon.antivpn.model.Allowlist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * The {@link Allowlist} repository.
 *
 * @author Braydon
 */
@Repository
public interface AllowlistRepository extends JpaRepository<Allowlist, Long> {
    /**
     * Find the allowlist with the given type.
     *
     * @param type the type of allowlist
     * @return the allowlist, null if none
     * @see Allowlist.AllowlistType for type
     */
    @Query("SELECT a FROM Allowlist a WHERE a.type = :type")
    Allowlist findByType(@NonNull Allowlist.AllowlistType type);
}
