package me.braydon.antivpn.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

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
}