package me.braydon.antivpn;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

@SpringBootApplication
@Slf4j(topic = "AntiVPN")
public class AntiVPN {
    public static final Gson GSON = new GsonBuilder()
                                        .serializeNulls()
                                        .create();
    
    @Value("${server.address}")
    private String address;
    
    @Value("${server.port}")
    private int port;
    
    @Value("${spring.data.redis.host}")
    private String redisHost;
    
    @Value("${spring.data.redis.port}")
    private int redisPort;
    
    @Value("${spring.data.redis.database}")
    private int redisDatabase;
    
    @Value("${spring.data.redis.auth}")
    private String redisAuth;
    
    @SneakyThrows
    public static void main(@NonNull String[] args) {
        File config = new File("application.yml");
        if (!config.exists()) { // Saving the default configuration if it doesn't exist
            Files.copy(Objects.requireNonNull(AntiVPN.class.getResourceAsStream("/application.yml")), config.toPath(), StandardCopyOption.REPLACE_EXISTING);
            log.info("Default configuration saved, please re-launch the application");
            return;
        }
        SpringApplication.run(AntiVPN.class, args); // Load the application
    }
    
    /**
     * Get the cors configuration.
     *
     * @return the configuration
     * @see WebMvcConfigurer for configuration
     */
    @Bean @NonNull
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@NonNull CorsRegistry registry) {
                registry.addMapping("/**").allowedOriginPatterns(
                    String.format("^(http|https)://%s:%s", address, port)
                );
            }
        };
    }
    
    /**
     * Build the config to use for Redis.
     *
     * @return the config
     * @see RedisTemplate for config
     */
    @Bean @NonNull
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(jedisConnectionFactory());
        return template;
    }
    
    /**
     * Build the connection factory to use
     * when making connections to Redis.
     *
     * @return the built factory
     * @see JedisConnectionFactory for factory
     */
    @Bean @NonNull
    public JedisConnectionFactory jedisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(redisHost, redisPort);
        config.setDatabase(redisDatabase);
        if (!redisAuth.trim().isEmpty()) { // Auth with our provided password
            config.setPassword(redisAuth);
        }
        return new JedisConnectionFactory(config);
    }
}