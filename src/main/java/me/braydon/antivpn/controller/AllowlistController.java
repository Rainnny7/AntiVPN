package me.braydon.antivpn.controller;

import lombok.NonNull;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.model.Allowlist;
import me.braydon.antivpn.service.PolicyListService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Manages allowlists, addresses on them are always reported as clean.
 *
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/allowlist", produces = MediaType.APPLICATION_JSON_VALUE)
public final class AllowlistController {
    @NonNull private final PolicyListService policyListService;
    
    public AllowlistController(@NonNull PolicyListService policyListService) {
        this.policyListService = policyListService;
    }
    
    /**
     * Modify the allowlist.
     * <p>
     * When this route is called, the given entry
     * will be added to the allowlist if it doesn't
     * exist, and removed if it does.
     * </p>
     *
     * @param type  the type of allowlist to modify
     * @param entry the IP address, CIDR block, or ASN to add/remove
     * @return the json response
     * @see Allowlist.AllowlistType for allowlist type
     */
    @PostMapping("/modify")
    public ResponseEntity<Map<String, String>> allowlist(@RequestParam @NonNull Allowlist.AllowlistType type,
                                                         @RequestParam @NonNull String entry) {
        AuthUtils.validatePermissions(APIKey.Permission.MANAGE_BLACKLIST); // Validate permissions
        boolean added = policyListService.toggleAllowlist(type, entry);
        return ResponseEntity.ok(Map.of(
            "allowlist", type.name(),
            "message", String.format("Entry '%s' was %s", entry.trim(), added ? "added" : "removed")
        ));
    }
    
    /**
     * List all allowlists.
     *
     * @return the json response
     */
    @GetMapping("/list")
    public ResponseEntity<List<Allowlist>> list() {
        AuthUtils.validatePermissions(APIKey.Permission.MANAGE_BLACKLIST); // Validate permissions
        return ResponseEntity.ok(policyListService.getAllAllowlists());
    }
}
