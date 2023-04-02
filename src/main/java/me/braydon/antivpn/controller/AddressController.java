package me.braydon.antivpn.controller;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.service.AddressService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.util.*;

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
     * This is used to perform lookups on an IP address.
     * </p>
     *
     * @return the json response
     * @see AddressService.AddressData#from for more
     */
    @GetMapping(value = "/check")
    @ResponseBody
    public ResponseEntity<?> check(@RequestParam @NonNull String ip, @RequestParam(required = false) Set<AddressService.AddressLookupData> data) {
        if (data == null) { // Default the list
            data = new HashSet<>();
        }
        AuthUtils.checkRateLimit(); // Checking for rate limit
        return ResponseEntity.ok(AddressService.AddressData.from(ip, data));
    }
    
    @PostMapping(value = "/blacklist")
    @ResponseBody
    public ResponseEntity<?> blacklist(@RequestParam @NonNull String ip, @RequestParam @NonNull AddressService.BlacklistType type) {
        AuthUtils.validatePermissions(APIKey.Permission.BLACKLIST_MODIFY); // Validate permissions
        return ResponseEntity.ok("(un?)blacklist " + ip + " in type " + type);
    }
    
    /**
     * The stats route.
     *
     * @return the json response
     */
    @GetMapping(value = "/stats")
    @ResponseBody
    public ResponseEntity<?> check() {
        AuthUtils.validatePermissions(APIKey.Permission.VIEW_STATS); // Validate permissions
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
        blacklisted.put("countries", AddressService.BLACKLISTED_COUNTRIES.size());
        stats.put("blacklisted", blacklisted);
        
        // Application stats
        stats.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        
        return ResponseEntity.ok(stats);
    }
}