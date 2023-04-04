package me.braydon.antivpn.blacklist;

import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * The {@link BlacklistType} repository.
 *
 * @author Braydon
 */
public interface BlacklistRepository extends MongoRepository<Blacklist, BlacklistType> {}
