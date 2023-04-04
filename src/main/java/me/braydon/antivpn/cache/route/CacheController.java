package me.braydon.antivpn.cache.route;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.cache.AddressCacheRepository;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.model.APIKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/cache", produces = MediaType.APPLICATION_JSON_VALUE)
@Slf4j(topic = "Cache Controller")
public final class CacheController {
    /**
     * The address cache repository.
     *
     * @see AddressCacheRepository for address cache repository
     */
    @NonNull private final AddressCacheRepository addressCacheRepository;
    
    @Autowired
    public CacheController(@NonNull AddressCacheRepository addressCacheRepository) {
        this.addressCacheRepository = addressCacheRepository;
    }
    
    /**
     * A route to purge the cache.
     *
     * @return the json response
     */
    @DeleteMapping("/purge")
    @ResponseBody
    public ResponseEntity<?> purge() {
        AuthUtils.validatePermissions(APIKey.Permission.PURGE_CACHE); // Validate permissions
        long before = addressCacheRepository.count();
        if (before == 0) { // Empty cache
            return ResponseEntity.ok(Map.of("message", "Cache is already empty"));
        }
        addressCacheRepository.deleteAll(); // Delete all cache elements
        long after = addressCacheRepository.count();
        return ResponseEntity.ok(Map.of("message", "Cache purged, removed " + (before - after) + " element(s)"));
    }
}
