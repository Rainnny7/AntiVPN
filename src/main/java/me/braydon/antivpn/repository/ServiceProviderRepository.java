package me.braydon.antivpn.repository;

import lombok.NonNull;
import me.braydon.antivpn.model.ServiceProviderIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * The {@link ServiceProviderIp} repository.
 *
 * @author Braydon
 */
@Repository
public interface ServiceProviderRepository extends JpaRepository<ServiceProviderIp, String> {
    /**
     * Find the id of the service provider
     * that has the given IP address.
     *
     * @param ipAddress the ip to search for
     * @return the id of the service provider, null if none
     */
    @Query("SELECT spi.provider FROM ServiceProviderIp spi WHERE spi.ip = :ipAddress")
    Integer findProviderIdByIpAddress(@NonNull String ipAddress);
    
    /**
     * Check if the given IP address is in the database.
     *
     * @param ipAddress the ip to search for
     * @return true if the ip is in the database, false otherwise
     */
    boolean existsByIp(@NonNull String ipAddress);
    
    /**
     * Get the IPs that belong to
     * the given service provider.
     *
     * @param providerId the id of the service provider
     * @return the IPs
     */
    @Query("SELECT spi.ip FROM ServiceProviderIp spi WHERE spi.provider = :providerId")
    List<String> getIps(int providerId);
    
    /**
     * Get the amount of IP addresses
     * that belong to the service provider
     * with the given id.
     *
     * @param providerId the id of the service provider
     * @return the amount of IP addresses
     */
    @Query("SELECT COUNT(spi) FROM ServiceProviderIp spi WHERE spi.provider = :providerId")
    int getIpCount(int providerId);
}