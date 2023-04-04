package me.braydon.antivpn.blacklist.route;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.blacklist.Blacklist;
import me.braydon.antivpn.blacklist.BlacklistType;
import me.braydon.antivpn.blacklist.repository.BlacklistRepository;
import me.braydon.antivpn.common.AuthUtils;
import me.braydon.antivpn.model.APIKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Map;

/**
 * @author Braydon
 */
@RestController
@RequestMapping(value = "/blacklist", produces = MediaType.APPLICATION_JSON_VALUE)
@Slf4j(topic = "Blacklist Controller")
public final class BlacklistController {
    /**
     * The blacklist repository.
     *
     * @see BlacklistRepository for blacklist repository
     */
    @NonNull private final BlacklistRepository blacklistRepository;
    
    @Autowired
    public BlacklistController(@NonNull BlacklistRepository blacklistRepository) {
        this.blacklistRepository = blacklistRepository;
    }
    
    /**
     * Modify the blacklist.
     * <p>
     * When this route is called, the given entry
     * will be added to the blacklist if it doesn't
     * exist, and removed if it does.
     * </p>
     *
     * @param type  the type of blacklist to modify
     * @param entry the entry to add/remove to/from the blacklist
     * @return the json response
     * @see Blacklist for blacklist
     * @see BlacklistType for blacklist type
     */
    @PostMapping("/modify")
    @ResponseBody
    public ResponseEntity<?> blacklist(@RequestParam @NonNull BlacklistType type, @RequestParam @NonNull Object entry) {
        AuthUtils.validatePermissions(APIKey.Permission.MANAGE_BLACKLIST); // Validate permissions
        if (entry instanceof String) { // Checking for empty entry string
            if (((String) entry).isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Entry cannot be empty"));
            }
        }
        Blacklist blacklist = blacklistRepository.findById(type).orElse(new Blacklist(type, new HashSet<>()));
        boolean added = false;
        if (blacklist.containsEntry(entry)) { // Removing the entry
            blacklist.removeEntry(entry);
        } else { // Adding the entry
            blacklist.addEntry(entry);
            added = true; // We added the entry
        }
        blacklistRepository.save(blacklist); // Save the new entries
        return ResponseEntity.ok(Map.of("message", "Entry was " + (added ? "added" : "removed")));
    }
    
    /**
     * List all blacklists.
     *
     * @return the json response
     * @see Blacklist for blacklist
     */
    @GetMapping("/list")
    @ResponseBody
    public ResponseEntity<?> list() {
        AuthUtils.validatePermissions(APIKey.Permission.MANAGE_BLACKLIST); // Validate permissions
        return ResponseEntity.ok(blacklistRepository.findAll());
    }
}
