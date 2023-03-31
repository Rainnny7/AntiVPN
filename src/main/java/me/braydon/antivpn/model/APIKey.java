package me.braydon.antivpn.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.Set;

/**
 * The API key model.
 *
 * @author Braydon
 */
@Document("apiKeys")
@AllArgsConstructor
@Getter
@ToString
public final class APIKey {
    /**
     * The API key.
     */
    @Id @NonNull private final String key;
    
    /**
     * The permissions this API key has.
     *
     * @see Permission for permissions
     */
    @NonNull private final Set<Permission> permissions;
    
    /**
     * The amount of uses this API key has.
     */
    public int uses;
    
    /**
     * The {@link Date} of when this API key was last used.
     */
    private Date lastUsed;
    
    /**
     * The {@link Date} this API key was created.
     */
    @NonNull private final Date creation;
    
    /**
     * Check if this API key has
     * any of the given permissions.
     *
     * @param permissions the permissions
     * @return true if has permissions, otherwise false
     * @see Permission for permission
     */
    public boolean hasPermission(@NonNull Permission... permissions) {
        for (Permission permission : permissions) {
            if (this.permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * This API key was used.
     * <p>
     * This will increment the uses and
     * update the last used {@link Date}.
     * </p>
     */
    public void use() {
        uses++;
        lastUsed = new Date();
    }
    
    public enum Permission {
        /**
         * Allows modification of blacklists.
         */
        BLACKLIST_MODIFY
    }
}