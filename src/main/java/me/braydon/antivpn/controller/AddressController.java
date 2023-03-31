package me.braydon.antivpn.controller;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.service.AddressService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
@Slf4j(topic = "Address Controller")
public class AddressController {
    /**
     * The check route.
     * <p>
     * This is used to determine a risk score for any given IPv4 address.
     * The risk score is calculated based on whether the address is in any
     * blacklists and/or the ASN, Country, or hostname of the originating
     * address is blacklisted.
     * </p>
     *
     * @param ip the address to check
     * @return the json response
     */
    @GetMapping(value = "/check")
    @ResponseBody
    public ResponseEntity<?> check(@RequestParam @NonNull String ip) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        //        authentication.getAuthorities().has
        
        return ResponseEntity.ok(AddressService.AddressData.from(ip));
    }
    
    @PostMapping(value = "/blacklist")
    @ResponseBody
    public ResponseEntity<?> blacklist(@RequestParam @NonNull String ip, @RequestParam @NonNull BlacklistType type) {
        return ResponseEntity.ok("TESTING");
    }
    
    /**
     * The stats route.
     *
     * @return the json response
     */
    @GetMapping(value = "/stats")
    @ResponseBody
    public ResponseEntity<?> check() {
        LinkedHashMap<String, Object> stats = new LinkedHashMap<>();
        
        // Stat to show IPs per provider
        Map<String, Integer> ips = new HashMap<>();
        for (VPNServiceProvider provider : VPNServiceProvider.getRegistry()) {
            ips.put(provider.getName(), provider.getIps().size());
        }
        stats.put("ips", ips);
        
        // Blacklisted stats
        Map<String, Integer> blacklisted = new HashMap<>();
        blacklisted.put("asns", AddressService.BLACKLISTED_ASN_NUMBERS.size());
        blacklisted.put("hostnames", 0);
        blacklisted.put("countries", 0);
        stats.put("blacklisted", blacklisted);
        
        // Application stats
        stats.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        
        return ResponseEntity.ok(stats);
    }
    
    /**
     * The type of a blacklist.
     */
    public enum BlacklistType {
        ASN,
        HOSTNAME,
        COUNTRY
    }
}