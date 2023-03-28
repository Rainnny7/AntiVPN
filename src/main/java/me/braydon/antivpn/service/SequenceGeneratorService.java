package me.braydon.antivpn.service;

import lombok.NonNull;
import me.braydon.antivpn.model.DatabaseSequence;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * @author Braydon
 */
@Service
public class SequenceGeneratorService {
    @NonNull private final MongoOperations mongoOperations;
    
    @Autowired
    public SequenceGeneratorService(@NonNull MongoOperations mongoOperations) {
        this.mongoOperations = mongoOperations;
    }
    
    /**
     * Generate the sequence
     * with the given name.
     *
     * @param seqName the name of the sequence
     * @return the sequence number
     */
    public long generateSequence(@NonNull String seqName) {
        DatabaseSequence counter = mongoOperations.findAndModify(Query.query(Criteria.where("_id").is(seqName)),
            new Update().inc("seq", 1), FindAndModifyOptions.options().returnNew(true).upsert(true),
            DatabaseSequence.class
        );
        return !Objects.isNull(counter) ? counter.getSeq() : 1;
    }
}