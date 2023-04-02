package me.braydon.antivpn.controller;

import com.google.gson.JsonObject;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.common.MemoryFormatter;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.provider.VPNServiceProvider;
import me.braydon.antivpn.service.AddressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
@Slf4j(topic = "Address Controller")
public class AddressController {
    @NonNull private final JedisConnectionFactory jedisFactory;
    
    @Autowired
    public AddressController(@NonNull JedisConnectionFactory jedisFactory) {
        this.jedisFactory = jedisFactory;
    }
    
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
        return ResponseEntity.ok(AddressService.AddressData.from(jedisFactory, ip, data));
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
        Runtime runtime = Runtime.getRuntime(); // The current runtime environment
        long totalMemory = runtime.totalMemory();
        long usedMemory = totalMemory - runtime.freeMemory();
        long maxMemory = runtime.maxMemory();
        long freeMemory = maxMemory - usedMemory;
        
        JsonObject jsonObject = new JsonObject(); // The json object to return
        
        // Stat to show IPs per provider
        JsonObject ipsJsonObject = new JsonObject();
        int total = 0;
        for (Map.Entry<String, Integer> entry : VPNServiceProvider.getProviderIpCounts(jedisFactory).entrySet()) {
            int ipCount = entry.getValue();
            ipsJsonObject.addProperty(entry.getKey(), ipCount);
            total += ipCount;
        }
        ipsJsonObject.addProperty("total", total); // Adding the total ip count
        jsonObject.add("ips", ipsJsonObject); // Adding the ips object to the main json object
        
        // Blacklisted stats
        JsonObject blacklistedJsonObject = new JsonObject();
        blacklistedJsonObject.addProperty("asns", AddressService.BLACKLISTED_ASN_NUMBERS.size());
        blacklistedJsonObject.addProperty("countries", AddressService.BLACKLISTED_COUNTRIES.size());
        jsonObject.add("blacklisted", blacklistedJsonObject); // Adding the blacklist object to the main json object
        
        // Application stats
        JsonObject applicationJsonObject = new JsonObject();
        applicationJsonObject.addProperty("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        applicationJsonObject.addProperty("availableProcessors", runtime.availableProcessors());
        
        JsonObject memoryJsonObject = new JsonObject();
        memoryJsonObject.addProperty("used", MemoryFormatter.format(usedMemory));
        memoryJsonObject.addProperty("max", MemoryFormatter.format(maxMemory));
        memoryJsonObject.addProperty("total", MemoryFormatter.format(totalMemory));
        memoryJsonObject.addProperty("free", MemoryFormatter.format(freeMemory));
        applicationJsonObject.add("memory", memoryJsonObject);
        
        jsonObject.add("application", applicationJsonObject); // Adding the application object to the main json object
        
        return ResponseEntity.ok(AntiVPN.GSON.toJson(jsonObject));
    }
}