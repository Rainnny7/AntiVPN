package me.braydon.antivpn.common;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;
import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.AntiVPN;
import me.braydon.antivpn.exception.impl.APIException;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request metadata attached to a lookup, such as a Minecraft player name.
 *
 * @author Braydon
 */
@UtilityClass
public final class LookupMetadata {
    /**
     * The maximum number of metadata entries kept.
     */
    public static final int MAX_ENTRIES = 20;
    
    /**
     * The maximum length of a metadata key.
     */
    public static final int MAX_KEY_LENGTH = 64;
    
    /**
     * The maximum length of a metadata value.
     */
    public static final int MAX_VALUE_LENGTH = 256;
    
    /**
     * Read metadata from a lookup request.
     * <p>
     * Accepts a JSON object in the {@code metadata} parameter,
     * {@code metadata.player=Steve} query parameters, and
     * {@code metadata[player]=Steve} query parameters.
     * </p>
     *
     * @param request the request
     * @return the metadata, empty if none was supplied
     * @throws APIException if {@code metadata} is present but not a JSON object
     */
    @NonNull
    public static Map<String, String> fromRequest(@NonNull HttpServletRequest request) {
        Map<String, String> metadata = new LinkedHashMap<>();
        String json = request.getParameter("metadata");
        if (json != null && !json.isBlank()) {
            metadata.putAll(fromJson(json));
        }
        for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            String dotted = dottedKey(entry.getKey());
            if (dotted == null || entry.getValue() == null || entry.getValue().length == 0) {
                continue;
            }
            put(metadata, dotted, entry.getValue()[0]);
        }
        return Collections.unmodifiableMap(metadata);
    }
    
    /**
     * Sanitize a metadata map from a JSON body.
     *
     * @param raw the raw metadata, or null
     * @return the sanitized metadata, empty if none was supplied
     */
    @NonNull
    public static Map<String, String> fromMap(Map<?, ?> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        Map<String, String> metadata = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            put(metadata, String.valueOf(entry.getKey()), stringify(entry.getValue()));
        }
        return Collections.unmodifiableMap(metadata);
    }
    
    @NonNull
    static Map<String, String> fromJson(@NonNull String json) {
        String trimmed = json.trim();
        if (!trimmed.startsWith("{")) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Metadata must be a JSON object");
        }
        JsonElement element;
        try (JsonReader reader = new JsonReader(new StringReader(trimmed))) {
            reader.setLenient(false);
            element = AntiVPN.GSON.fromJson(reader, JsonElement.class);
        } catch (JsonParseException | IllegalStateException | IOException ex) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Invalid metadata JSON");
        }
        if (element == null || !element.isJsonObject()) {
            throw new APIException(HttpStatus.BAD_REQUEST, "Metadata must be a JSON object");
        }
        Map<String, String> metadata = new LinkedHashMap<>();
        JsonObject object = element.getAsJsonObject();
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            put(metadata, entry.getKey(), stringify(entry.getValue()));
        }
        return metadata;
    }
    
    private static String dottedKey(@NonNull String parameter) {
        if (parameter.startsWith("metadata.") && parameter.length() > "metadata.".length()) {
            return parameter.substring("metadata.".length());
        }
        if (parameter.startsWith("metadata[") && parameter.endsWith("]") && parameter.length() > "metadata[]".length()) {
            return parameter.substring("metadata[".length(), parameter.length() - 1);
        }
        return null;
    }
    
    private static void put(@NonNull Map<String, String> metadata, String key, String value) {
        if (metadata.size() >= MAX_ENTRIES || key == null || value == null) {
            return;
        }
        String sanitizedKey = truncate(key.trim(), MAX_KEY_LENGTH);
        String sanitizedValue = truncate(value.trim(), MAX_VALUE_LENGTH);
        if (sanitizedKey.isEmpty() || sanitizedValue.isEmpty()) {
            return;
        }
        metadata.put(sanitizedKey, sanitizedValue);
    }
    
    private static String stringify(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof JsonElement element) {
            if (element.isJsonNull()) {
                return null;
            }
            if (element.isJsonPrimitive()) {
                return element.getAsString();
            }
            return AntiVPN.GSON.toJson(element);
        }
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        return AntiVPN.GSON.toJson(value);
    }
    
    @NonNull
    private static String truncate(@NonNull String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
