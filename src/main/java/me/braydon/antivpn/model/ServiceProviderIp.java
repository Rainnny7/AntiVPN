package me.braydon.antivpn.model;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import me.braydon.antivpn.provider.ServiceProvider;

import javax.persistence.*;

/**
 * An IP address that belongs
 * to a service provider.
 *
 * @author Braydon
 * @see ServiceProvider for service provider
 */
@Entity
@Table(name = "provider_ips", indexes = {
    @Index(columnList = "ip", unique = true)
})
@Setter
@Getter
@ToString
public class ServiceProviderIp {
    /**
     * The id of this ip entry.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private long id;
    
    /**
     * The id of the service provider
     * this entry belongs to.
     *
     * @see ServiceProvider for service provider
     */
    private int provider;
    
    /**
     * The serialized IP address of this entry.
     */
    @NonNull private String ip;
}
