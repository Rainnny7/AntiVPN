package me.braydon.antivpn.repository;

import me.braydon.antivpn.model.APIKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * The {@link APIKey} repository.
 */
@Repository
public interface APIKeyRepository extends JpaRepository<APIKey, String> {}