package me.braydon.antivpn.controller;

import lombok.Getter;
import lombok.Setter;
import me.braydon.antivpn.service.AddressService;

import java.util.Map;
import java.util.Set;

/**
 * JSON body for {@code POST /check}.
 *
 * @author Braydon
 */
@Getter @Setter
public class CheckRequest {
    /**
     * The IP address or domain to look up.
     */
    private String ip;
    
    /**
     * Extra data to include in the response.
     */
    private Set<AddressService.LookupData> data;
    
    /**
     * Whether to skip the cache.
     */
    private boolean ignoreCache;
    
    /**
     * Optional metadata to include in Discord logs, such as a player name.
     */
    private Map<String, Object> metadata;
}
