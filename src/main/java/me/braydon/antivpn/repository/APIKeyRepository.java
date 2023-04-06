package me.braydon.antivpn.repository;

import lombok.NonNull;
import me.braydon.antivpn.model.APIKey;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.UUID;

/**
 * The {@link APIKey} repository.
 *
 * @author Braydon
 */
public interface APIKeyRepository extends MongoRepository<APIKey, UUID> {
    /**
     * Find the api key object
     * with the given key.
     *
     * @param key the api key
     * @return the api key, null if none
     * @see APIKey for api key
     */
    @Query("{'key': '?0'}")
    APIKey findByKey(@NonNull String key);
    
    /**
     * Get the total number of api keys.
     *
     * @return the amount of api keys
     * @see APIKey for api key
     */
    long count();
}