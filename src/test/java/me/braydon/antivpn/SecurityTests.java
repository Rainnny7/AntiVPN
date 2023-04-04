package me.braydon.antivpn;

import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.security.APIKeyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.Preconditions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;

/**
 * @author Braydon
 */
@DataMongoTest(properties = {
    "spring.data.mongodb.uri=mongodb://admin:Fx2J8aU9e3bhnz2Viu2K@10.10.10.110:27017/antivpn_dev?authSource=admin",
})
public final class SecurityTests {
    /**
     * The api key repository.
     *
     * @see APIKeyRepository for api key repository
     */
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
        APIKey apiKey = APIKey.generate("Generated from security test", APIKey.Permission.values()); // Generate the API key
        Preconditions.condition(apiKey.equals(apiKeyRepository.save(apiKey)),
            "Failed saving the API key"); // Validate the API key was saved successfully
        System.out.printf("Created a fully privileged API key: %s%n", apiKey.getKey()); // Log the creation
    }
}