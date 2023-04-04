package me.braydon.antivpn.blacklist.repository;

import me.braydon.antivpn.blacklist.Blacklist;
import me.braydon.antivpn.blacklist.BlacklistType;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * The {@link BlacklistType} repository.
 *
 * @author Braydon
 */
public interface BlacklistRepository extends MongoRepository<Blacklist, BlacklistType>, CustomBlacklistRepository {}