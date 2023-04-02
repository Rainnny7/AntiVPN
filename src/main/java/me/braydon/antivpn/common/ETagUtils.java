package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.AntiVPN;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;

import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

/**
 * @author Braydon
 */
@UtilityClass
@Slf4j(topic = "ETags")
public final class ETagUtils {
    /**
     * Generate an eTag for the response.
     *
     * @param bodyBuilder the response builder
     * @param body        the response body
     * @param <T>         the type of the response body
     * @return the response entity
     * @see ResponseEntity.BodyBuilder for response body builder
     * @see ResponseEntity for response entity
     */
    @NonNull @SneakyThrows
    public static <T> ResponseEntity<T> generateFor(@NonNull ResponseEntity.BodyBuilder bodyBuilder, @NonNull T body) {
        String json = AntiVPN.GSON.toJson(body); // Convert the response body to json
        byte[] capturedContent = json.getBytes(); // The bytes of the response content
        
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(capturedContent);
        StringBuilder builder = new StringBuilder();
        for (byte contentByte : hash) { // Build the hex string
            builder.append(String.format("%02x", contentByte));
        }
        String hex = builder.toString(); // The hex from the response content
        String etag = "\"" + hex + "\"";
        
        bodyBuilder.eTag(etag); // Set the eTag for the response
        bodyBuilder.cacheControl(CacheControl.maxAge(1L, TimeUnit.HOURS)); // Cache the response for 1 hour
        return bodyBuilder.body(body); // Return the response entity
    }
}
