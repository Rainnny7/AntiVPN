package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.exception.APIException;
import me.braydon.antivpn.exception.RateLimitException;
import me.braydon.antivpn.model.APIKey;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Braydon
 */
@UtilityClass
public final class AuthUtils {
    /**
     * Check if this currently authenticated API
     * key has any of the given permissions.
     *
     * @param permissions the permissions
     * @throws IllegalStateException if no API key is found
     * @throws LockedException       if permissions are not met
     * @see APIKey for api key
     * @see APIKey.Permission for permission
     */
    public static void validatePermissions(@NonNull APIKey.Permission... permissions) {
        APIKey apiKey = getCurrentAPIKey(); // Get the current API key
        if (apiKey.hasPermission(permissions)) { // Has permissions, no need to throw an exception
            return;
        }
        throw new APIException(HttpStatus.FORBIDDEN, new LockedException("Lacking permissions"));
    }
    
    /**
     * Check if this currently authenticated
     * API key is rate limited.
     *
     * @throws RateLimitException if rate limited
     */
    public static void checkRateLimit() throws RateLimitException {
        APIKey apiKey = getCurrentAPIKey(); // Get the current API key
        if (apiKey.checkRateLimit()) { // The API key is rate limited
            throw new RateLimitException();
        }
    }
    
    /**
     * Get the currently authenticated API key.
     *
     * @return the api key
     * @throws IllegalStateException if no API key is found
     * @see APIKey for api key
     */
    @NonNull
    public APIKey getCurrentAPIKey() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object credentials;
        if (authentication != null && ((credentials = authentication.getCredentials()) != null)) { // Authentication
            return (APIKey) credentials;
        }
        throw new IllegalStateException("No API key found in current session");
    }
}
