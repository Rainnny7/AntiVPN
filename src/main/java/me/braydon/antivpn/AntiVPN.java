package me.braydon.antivpn;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

import jakarta.annotation.PostConstruct;
import java.net.http.HttpClient;
import java.time.Duration;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
@Slf4j(topic = "AntiVPN")
public class AntiVPN {
    public static final Gson GSON = new GsonBuilder()
                                        .serializeNulls()
                                        .setDateFormat("MM-dd-yyyy")
                                        .create();
    public static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                                                     .followRedirects(HttpClient.Redirect.NORMAL)
                                                     .connectTimeout(Duration.ofSeconds(10L))
                                                     .build(); // The HTTP client to use
    @Getter private static boolean development;
    
    /**
     * Are we in a development environment?
     */
    @Value("${dev:false}")
    private boolean dev;
    
    public static void main(@NonNull String[] args) {
        SpringApplication.run(AntiVPN.class, args); // Load the application
    }
    
    @PostConstruct
    public void initialize() {
        development = dev; // Are we using a development environment?
    }
}
