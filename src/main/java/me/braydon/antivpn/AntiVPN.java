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

import javax.annotation.PostConstruct;
import java.io.File;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SpringBootApplication
@Slf4j(topic = "AntiVPN")
public class AntiVPN {
    public static final Gson GSON = new GsonBuilder()
                                        .serializeNulls()
                                        .create();
    public static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                                                     .followRedirects(HttpClient.Redirect.ALWAYS)
                                                     .build(); // The HTTP client to use
    /**
     * The thread pool to use for scraping of providers.
     *
     * @see ExecutorService for thread pool
     */
    public static ExecutorService THREAD_POOL;
    private static int INDEXED_THREAD_COUNT; // The indexed thread count
    
    /**
     * The Redis server host.
     */
    @Value("${spring.data.redis.host}")
    private String redisHost;
    
    /**
     * The Redis server port.
     */
    @Value("${spring.data.redis.port}")
    private int redisPort;
    
    /**
     * The Redis database index.
     */
    @Value("${spring.data.redis.database}")
    private int redisDatabase;
    
    /**
     * The optional Redis password.
     */
    @Value("${spring.data.redis.auth}")
    private String redisAuth;
    
    /**
     * The amount of threads to use for the thread pool.
     *
     * @see ExecutorService for thread pool
     */
    @Value("${threads}")
    private int threads;
    
    @SneakyThrows
    public static void main(@NonNull String[] args) {
        File config = new File("application.yml");
        if (!config.exists()) { // Saving the default config if it doesn't exist locally
            Files.copy(Objects.requireNonNull(AntiVPN.class.getResourceAsStream("/application.yml")), config.toPath(), StandardCopyOption.REPLACE_EXISTING);
            log.info("Saved the default configuration to '{}', please re-launch the application", // Log the default config being saved
                config.getAbsolutePath()
            );
            return;
        }
        log.info("Found configuration at '{}'", config.getAbsolutePath()); // Log the found config
        SpringApplication.run(AntiVPN.class, args); // Load the application
    }
    
    @PostConstruct
    public void initialize() {
        // Setup the thread pool
        THREAD_POOL = Executors.newFixedThreadPool(threads, task -> {
            return new Thread(task, "AntiVPN #" + (INDEXED_THREAD_COUNT++)); // Create a new thread
        });
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