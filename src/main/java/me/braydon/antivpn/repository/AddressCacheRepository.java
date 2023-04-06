package me.braydon.antivpn.repository;

import me.braydon.antivpn.cache.CachedAddressData;
import org.springframework.data.repository.CrudRepository;

/**
 * The {@link CachedAddressData} repository.
 *
 * @author Braydon
 */
public interface AddressCacheRepository extends CrudRepository<CachedAddressData, String> {}
