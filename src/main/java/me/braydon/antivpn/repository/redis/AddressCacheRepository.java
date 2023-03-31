package me.braydon.antivpn.repository.redis;

import me.braydon.antivpn.cache.AddressCache;
import org.springframework.data.repository.CrudRepository;

/**
 * The {@link AddressCache} repository.
 *
 * @author Braydon
 */
public interface AddressCacheRepository extends CrudRepository<AddressCache, String> {}