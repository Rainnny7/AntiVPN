package me.braydon.antivpn.config;

import me.braydon.antivpn.model.APIKey;
import me.braydon.antivpn.repository.APIKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class APIKeyInitializerTest {
    private static final String ADMIN_KEY = "admin-key-0123456789abcdef";
    
    private final Map<String, APIKey> keys = new HashMap<>();
    private APIKeyRepository repository;
    
    @BeforeEach
    void setUp() {
        repository = mock(APIKeyRepository.class);
        when(repository.count()).thenAnswer(invocation -> (long) keys.size());
        when(repository.findById(anyString())).thenAnswer(invocation -> Optional.ofNullable(keys.get(invocation.<String>getArgument(0))));
        when(repository.findByDescription(anyString())).thenAnswer(invocation -> keys.values().stream()
            .filter(key -> key.getDescription().equals(invocation.getArgument(0))).toList());
        when(repository.save(any())).thenAnswer(invocation -> {
            APIKey key = invocation.getArgument(0);
            keys.put(key.getSecret(), key);
            return key;
        });
        doAnswer(invocation -> keys.remove(invocation.<APIKey>getArgument(0).getSecret())).when(repository).delete(any());
    }
    
    private void run(String adminKey) {
        new APIKeyInitializer(repository, adminKey).run(new DefaultApplicationArguments());
    }
    
    @Test
    void createsTheAdminKeyWithEveryPermission() {
        run(ADMIN_KEY);
        
        assertThat(keys).containsOnlyKeys(ADMIN_KEY);
        assertThat(keys.get(ADMIN_KEY).getPermissions()).containsExactlyInAnyOrder(APIKey.Permission.values());
    }
    
    @Test
    void upgradesAnExistingKey() {
        APIKey existing = APIKey.create(ADMIN_KEY, "Old", APIKey.Permission.VIEW_STATS);
        existing.setBanned(new Date());
        keys.put(ADMIN_KEY, existing);
        
        run(ADMIN_KEY);
        
        APIKey admin = keys.get(ADMIN_KEY);
        assertThat(admin.getPermissions()).containsExactlyInAnyOrder(APIKey.Permission.values());
        assertThat(admin.isBanned()).isFalse();
        assertThat(admin.getDescription()).isEqualTo(APIKeyInitializer.ADMIN_DESCRIPTION);
    }
    
    @Test
    void revokesThePreviousAdminKey() {
        run("previous-admin-key-0123456789");
        run(ADMIN_KEY);
        
        assertThat(keys).containsOnlyKeys(ADMIN_KEY);
    }
    
    @Test
    void keepsOtherKeys() {
        APIKey other = APIKey.create("customer-key", "Customer", APIKey.Permission.VIEW_STATS);
        keys.put(other.getSecret(), other);
        
        run(ADMIN_KEY);
        
        assertThat(keys).containsOnlyKeys(ADMIN_KEY, "customer-key");
        assertThat(keys.get("customer-key").getPermissions()).isEqualTo(Set.of(APIKey.Permission.VIEW_STATS));
    }
    
    @Test
    void rejectsShortAdminKeys() {
        assertThatThrownBy(() -> run("too-short")).isInstanceOf(IllegalStateException.class);
        assertThat(keys).isEmpty();
    }
    
    @Test
    void generatesADefaultKeyWithoutAnAdminKey() {
        run("");
        
        assertThat(keys).hasSize(1);
        assertThat(keys.values().iterator().next().getPermissions()).containsExactlyInAnyOrder(APIKey.Permission.values());
    }
    
    @Test
    void doesNotGenerateWhenKeysExist() {
        keys.put("customer-key", APIKey.create("customer-key", "Customer"));
        
        run(" ");
        
        assertThat(keys).containsOnlyKeys("customer-key");
        assertThat(List.copyOf(keys.values()).getFirst().getPermissions()).isEmpty();
    }
}
