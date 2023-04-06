package me.braydon.antivpn.common;

import com.google.gson.JsonElement;
import lombok.*;
import me.braydon.antivpn.AntiVPN;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * @author Braydon
 */
@Builder @ToString
public class WebRequest {
    /**
     * The URL of this request.
     */
    @NonNull private final String url;
    
    /**
     * The method of this request.
     */
    @Builder.Default @NonNull private String method = "GET";
    
    /**
     * The body publisher of this request.
     *
     * @see HttpRequest.BodyPublisher for body publisher
     */
    @Builder.Default @NonNull private HttpRequest.BodyPublisher bodyPublisher = HttpRequest.BodyPublishers.noBody();
    
    /**
     * The headers of this request.
     */
    @Singular @NonNull private Map<String, String> headers;
    
    /**
     * Send this request and get
     * JSON as the response.
     *
     * @return the response JSON
     * @see JsonElement for JSON
     */
    @NonNull
    public JsonElement sendAsJson() {
        return AntiVPN.GSON.fromJson(send(HttpResponse.BodyHandlers.ofString()), JsonElement.class);
    }
    
    /**
     * Send this request and get an
     * input stream as the response.
     *
     * @return the response input stream
     * @see InputStream for input stream
     */
    @NonNull
    public InputStream sendAsInputStream() {
        return send(HttpResponse.BodyHandlers.ofInputStream());
    }
    
    /**
     * Send this request.
     *
     * @param bodyHandler the body handler
     * @param <T>         the type of the response body
     * @return the response body
     * @see HttpResponse.BodyHandler for body handler
     * @see HttpResponse for response
     */
    @SneakyThrows @NonNull
    public <T> T send(@NonNull HttpResponse.BodyHandler<T> bodyHandler) {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                                 .uri(URI.create(url))
                                                 .method(method, bodyPublisher)
                                                 .timeout(Duration.ofSeconds(20L));
        for (Map.Entry<String, String> entry : headers.entrySet()) { // Adding headers
            requestBuilder.header(entry.getKey(), entry.getValue());
        }
        HttpRequest request = requestBuilder.build(); // Build the request
        HttpResponse<T> response = AntiVPN.HTTP_CLIENT.send(request, bodyHandler);
        if (response.statusCode() != 200) { // If the status code is not 200
            throw new IllegalStateException(String.format("Bad status code (%s) returned", response.statusCode()));
        }
        return response.body();
    }
}