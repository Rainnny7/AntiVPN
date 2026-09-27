package me.braydon.antivpn.repository;

import me.braydon.antivpn.model.APIKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * The {@link APIKey} repository.
 */
@Repository
public interface APIKeyRepository extends JpaRepository<APIKey, String> {
    List<APIKey> findByDescription(String description);
}