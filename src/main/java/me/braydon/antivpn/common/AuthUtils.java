package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.model.APIKey;
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
     * @throws LockedException if permissions are not met
     * @see APIKey for api key
     * @see APIKey.Permission for permission
     */
    public static void validatePermissions(@NonNull APIKey.Permission... permissions) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object credentials;
        if (authentication != null && ((credentials = authentication.getCredentials()) != null)) { // Authentication
            APIKey apiKey = (APIKey) credentials;
            if (apiKey.hasPermission(permissions)) { // Has permissions, no need to throw an exception
                return;
            }
        }
        throw new LockedException("Lacking permissions");
    }
}
