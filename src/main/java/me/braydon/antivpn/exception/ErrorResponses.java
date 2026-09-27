package me.braydon.antivpn.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import me.braydon.antivpn.AntiVPN;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the JSON body used for every error response.
 *
 * @author Braydon
 */
@UtilityClass
public final class ErrorResponses {
    /**
     * Build an error body.
     *
     * @param status  the status
     * @param message the message
     * @param path    the request path
     * @return the body
     */
    @NonNull
    public static Map<String, Object> body(@NonNull HttpStatus status, String message, String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", path);
        return body;
    }
    
    /**
     * Write an error straight to a servlet response, for use outside of MVC (e.g. in filters).
     *
     * @param request  the request
     * @param response the response
     * @param status   the status
     * @param message  the message
     * @throws IOException if writing fails
     */
    public static void write(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                             @NonNull HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(AntiVPN.GSON.toJson(body(status, message, request.getRequestURI())));
    }
}
