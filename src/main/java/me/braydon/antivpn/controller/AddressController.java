package me.braydon.antivpn.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.common.ClientIpResolver;
import me.braydon.antivpn.common.LookupMetadata;
import me.braydon.antivpn.common.MemoryFormatter;
import me.braydon.antivpn.detection.DetectionService;
import me.braydon.antivpn.detection.DetectionSource;
import me.braydon.antivpn.detection.SourceState;
import me.braydon.antivpn.discord.DiscordWebhookService;
import me.braydon.antivpn.exception.impl.APIException;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.model.AddressData;
import me.braydon.antivpn.model.Allowlist;
import me.braydon.antivpn.model.Blacklist;
import me.braydon.antivpn.service.AddressService;
import me.braydon.antivpn.service.PolicyListService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.*;

/**
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
@Slf4j(topic = "Address Controller")
public class AddressController {
    @NonNull private final AddressService addressService;
    @NonNull private final DetectionService detectionService;
    @NonNull private final PolicyListService policyListService;
    @NonNull private final ClientIpResolver clientIpResolver;
    @NonNull private final DiscordWebhookService discordWebhookService;
    
    /**
     * Should we enable the /amiusingavpn route?
     */
    @Value("${amiusingavpn:false}")
    private boolean enableAmIUsingAVPN;
    
    public AddressController(@NonNull AddressService addressService, @NonNull DetectionService detectionService,
                             @NonNull PolicyListService policyListService, @NonNull ClientIpResolver clientIpResolver,
                             @NonNull DiscordWebhookService discordWebhookService) {
        this.addressService = addressService;
        this.detectionService = detectionService;
        this.policyListService = policyListService;
        this.clientIpResolver = clientIpResolver;
        this.discordWebhookService = discordWebhookService;
    }
    
    /**
     * The check route.
     * <p>
     * This is used to perform lookups on an IP address.
     * </p>
     *
     * @return the json response
     * @see AddressService#lookup for more
     */
    @GetMapping("/check")
    public ResponseEntity<AddressData> check(@RequestParam @NonNull String ip,
                                             @RequestParam(required = false) Set<AddressService.LookupData> data,
                                             @RequestParam(required = false) boolean ignoreCache,
                                             @NonNull HttpServletRequest request) {
        return performCheck(ip, data, ignoreCache, LookupMetadata.fromRequest(request));
    }
    
    /**
     * The check route, accepting a JSON body.
     * <p>
     * Same as {@code GET /check}, with optional {@code metadata}
     * (for example a Minecraft player name) included in Discord logs.
     * </p>
     *
     * @param body the lookup request
     * @return the json response
     * @see AddressService#lookup for more
     */
    @PostMapping("/check")
    public ResponseEntity<AddressData> check(@RequestBody @NonNull CheckRequest body) {
        if (body.getIp() == null || body.getIp().isBlank()) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Missing IP address");
        }
        return performCheck(body.getIp(), body.getData(), body.isIgnoreCache(), LookupMetadata.fromMap(body.getMetadata()));
    }
    
    /**
     * Check if the requesting IP is using a VPN.
     *
     * @param request the request
     * @return the json response
     */
    @GetMapping("/amiusingavpn")
    public ResponseEntity<?> amiusingavpn(@NonNull HttpServletRequest request) {
        if (!enableAmIUsingAVPN) { // Disallow in production
            return ResponseEntity.notFound().build();
        }
        AddressData addressData = addressService.lookup(clientIpResolver.resolve(request), Set.of(), false);
        boolean usingVpn = addressData.isVpn() || addressData.isTor();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", usingVpn ? "Yes, you're using a VPN" : "No, you're not using a VPN");
        body.put("ipType", addressData.getIpType());
        body.put("vpn", addressData.isVpn());
        body.put("tor", addressData.isTor());
        body.put("relay", addressData.isRelay());
        if (addressData.getProvider() != null) {
            body.put("provider", addressData.getProvider());
        }
        return ResponseEntity.ok(body);
    }
    
    /**
     * Look up an address and optionally post the result to Discord.
     *
     * @param ip          the ip or domain
     * @param data        extra data to include
     * @param ignoreCache whether to skip the cache
     * @param metadata    request metadata for Discord logs
     * @return the json response
     */
    @NonNull
    private ResponseEntity<AddressData> performCheck(@NonNull String ip, Set<AddressService.LookupData> data,
                                                     boolean ignoreCache, @NonNull Map<String, String> metadata) {
        AuthUtils.checkRateLimit(); // Checking for rate limit
        if (ignoreCache) { // Validate permissions to ignore the cache
            AuthUtils.validatePermissions(APIKey.Permission.IGNORE_ADDRESS_CACHE);
        }
        AddressData addressData = addressService.lookup(ip, data == null ? Set.of() : data, ignoreCache);
        discordWebhookService.logLookup(addressData, metadata);
        return ResponseEntity.ok(addressData);
    }
    
    /**
     * The stats route.
     *
     * @return the json response
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {
        AuthUtils.validatePermissions(APIKey.Permission.VIEW_STATS); // Validate permissions
        Instant now = Instant.now();
        
        // Stat to show blocks per source
        Map<String, Integer> ips = new LinkedHashMap<>();
        Map<String, Object> sources = new LinkedHashMap<>();
        int total = 0;
        for (SourceState state : detectionService.getStates()) {
            DetectionSource source = state.getSource();
            int blocks = state.getIndex().size();
            ips.put(source.getName(), blocks);
            total += blocks;
            
            Map<String, Object> sourceStats = new LinkedHashMap<>();
            sourceStats.put("name", source.getName());
            sourceStats.put("category", source.getCategory());
            sourceStats.put("confidence", source.getConfidence());
            sourceStats.put("blocks", blocks);
            sourceStats.put("updatedAt", state.getUpdatedAt());
            sourceStats.put("stale", detectionService.isStale(state, now));
            sourceStats.put("lastError", state.getLastError());
            sources.put(source.getId(), sourceStats);
        }
        ips.put("total", total);
        
        // Blacklisted and allowlisted stats
        Map<String, Integer> blacklisted = new LinkedHashMap<>();
        for (Blacklist blacklist : policyListService.getAllBlacklists()) {
            blacklisted.put(blacklist.getType().name(), blacklist.getEntries().size());
        }
        Map<String, Integer> allowlisted = new LinkedHashMap<>();
        for (Allowlist allowlist : policyListService.getAllAllowlists()) {
            allowlisted.put(allowlist.getType().name(), allowlist.getEntries().size());
        }
        
        // Application stats
        Runtime runtime = Runtime.getRuntime(); // The current runtime environment
        long totalMemory = runtime.totalMemory();
        long usedMemory = totalMemory - runtime.freeMemory();
        long maxMemory = runtime.maxMemory();
        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("used", MemoryFormatter.format(usedMemory));
        memory.put("max", MemoryFormatter.format(maxMemory));
        memory.put("total", MemoryFormatter.format(totalMemory));
        memory.put("free", MemoryFormatter.format(maxMemory - usedMemory));
        
        Map<String, Object> application = new LinkedHashMap<>();
        application.put("environment", AntiVPN.isDevelopment() ? "dev" : "prod");
        application.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        application.put("availableProcessors", runtime.availableProcessors());
        application.put("memory", memory);
        
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ips", ips);
        body.put("sources", sources);
        body.put("blacklisted", blacklisted);
        body.put("allowlisted", allowlisted);
        body.put("application", application);
        return ResponseEntity.ok(body);
    }
}
