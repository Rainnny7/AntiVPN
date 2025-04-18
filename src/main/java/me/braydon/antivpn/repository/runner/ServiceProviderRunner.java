package me.braydon.antivpn.repository.runner;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.provider.ServiceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.function.Consumer;

/**
 * This runner will compress necessary
 * tables for {@link ServiceProvider}'s.
 *
 * @author Braydon
 */
@Component
@Slf4j(topic = "Service Provider Runner")
public final class ServiceProviderRunner implements CommandLineRunner {
    @NonNull private final JdbcTemplate jdbcTemplate;
    
    @Autowired
    public ServiceProviderRunner(@NonNull JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    
    @Override
    public void run(String... args) {
        Consumer<String> compressTable = tableName -> { // Compression function
            String query = "ALTER TABLE " + tableName + " ENGINE=InnoDB, ROW_FORMAT=COMPRESSED;";
            jdbcTemplate.execute(query);
            log.info("Compressed table \"{}\"", tableName); // Log the table compression
        };
        compressTable.accept("provider_ips"); // Compress the IPs table
    }
}
