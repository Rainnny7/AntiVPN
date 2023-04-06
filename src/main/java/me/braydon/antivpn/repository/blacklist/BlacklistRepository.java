package me.braydon.antivpn.repository.blacklist;

import me.braydon.antivpn.model.Blacklist;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * The {@link Blacklist.BlacklistType} repository.
 *
 * @author Braydon
 */
public interface BlacklistRepository extends MongoRepository<Blacklist, Blacklist.BlacklistType>, CustomBlacklistRepository {}