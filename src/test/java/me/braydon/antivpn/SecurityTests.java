package me.braydon.antivpn;

import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.mongodb.APIKeyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.Preconditions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;

import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * @author Braydon
 */
@DataMongoTest(properties = {
    "spring.data.mongodb.uri=mongodb://admin:Fx2J8aU9e3bhnz2Viu2K@10.10.10.110:27017/antivpn?authSource=admin",
})
public final class SecurityTests {
    @Autowired private APIKeyRepository apiKeyRepository;
    
    /**
     * A test to generate a fully privileged API key.
     *
     * @see APIKey for api key
     * @see APIKey.Permission for granted permissions
     */
    @DisplayName("Generate a fully privileged API key")
    @Test
    public void fullyPrivilegedApiKey() {
        // Generate the API key
        APIKey apiKey = new APIKey(UUID.randomUUID().toString(), Set.of(APIKey.Permission.values()), 0, null, new Date());
        
        // Validate the API key was saved successfully
        Preconditions.condition(apiKey.equals(apiKeyRepository.save(apiKey)), "Failed saving the API key");
        
        // Log the creation
        System.out.printf("Created a fully privileged API key: %s%n", apiKey.getKey());
    }
}