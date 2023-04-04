package me.braydon.antivpn.blacklist.repository;

import lombok.NonNull;
import me.braydon.antivpn.blacklist.Blacklist;
import me.braydon.antivpn.blacklist.BlacklistType;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

/**
 * The implementation of our
 * custom blacklist's repository.
 *
 * @author Braydon
 * @see CustomBlacklistRepository for the interface
 */
public final class BlacklistRepositoryImpl implements CustomBlacklistRepository {
    @Autowired private MongoTemplate mongoTemplate;
    
    /**
     * Check if the blacklist with the given
     * type contains any of the given entries.
     *
     * @param type    the type of blacklist
     * @param entries the entries to check
     * @return true if true, otherwise false
     * @see BlacklistType for type
     */
    @Override
    public boolean contains(@NonNull BlacklistType type, @NotNull @NonNull Object... entries) {
        Query query = new Query();
        query.addCriteria(Criteria.where("_id")
                              .is(type)
                              .and("entries")
                              .in(entries));
        return mongoTemplate.exists(query, Blacklist.class);
    }
}
