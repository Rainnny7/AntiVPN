package me.braydon.antivpn.model;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author Braydon
 */
@Document(collection = "database_sequences")
@Setter
@Getter
public class DatabaseSequence {
    /**
     * The id of this sequence.
     */
    @Id @NonNull private String id;
    
    /**
     * The sequence number.
     */
    private long seq;
}