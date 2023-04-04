package me.braydon.antivpn.cache;

import org.springframework.data.repository.CrudRepository;

/**
 * The {@link CachedAddressData} repository.
 *
 * @author Braydon
 */
public interface AddressCacheRepository extends CrudRepository<CachedAddressData, String> {}
