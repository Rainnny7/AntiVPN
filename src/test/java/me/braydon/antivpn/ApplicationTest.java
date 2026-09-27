package me.braydon.antivpn;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The application on an in-memory H2 database, with Redis unavailable
 * (lookups must still work, just without caching).
 */
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:antivpn;MODE=MariaDB;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.data.redis.port=1",
    "spring.data.redis.timeout=250ms",
    "spring.data.redis.connect-timeout=250ms",
    "auth.admin-key=" + ApplicationTest.ADMIN_KEY
})
class ApplicationTest extends AbstractApplicationTest {
    static final String ADMIN_KEY = "test-admin-key-0123456789";
    
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        snapshotDirectory(registry);
    }
    
    @Test
    void configuredAdminKeyHasEveryPermission() throws Exception {
        mvc.perform(get("/stats").header("X-API-Key", ADMIN_KEY)).andExpect(status().isOk());
        mvc.perform(get("/allowlist/list").header("X-API-Key", ADMIN_KEY)).andExpect(status().isOk());
    }
    
    @Test
    void configuredAdminKeyIsNotRateLimited() throws Exception {
        for (int i = 0; i < 50; i++) { // Well over the default 10 per second
            mvc.perform(get("/check").param("ip", "1.128.0.1").header("X-API-Key", ADMIN_KEY)).andExpect(status().isOk());
        }
    }
}
