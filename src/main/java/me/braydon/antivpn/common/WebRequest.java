package me.braydon.antivpn.common;

import com.google.gson.JsonElement;
import lombok.*;
import me.braydon.antivpn.AntiVPN;

import java.io.IOException;
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
    private static final String USER_AGENT = "AntiVPN (+https://github.com/Rainnny7/AntiVPN)";
    
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
     * The timeout of this request.
     */
    @Builder.Default @NonNull private Duration timeout = Duration.ofSeconds(30L);
    
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
    public JsonElement sendAsJson() throws IOException, InterruptedException {
        return AntiVPN.GSON.fromJson(sendAsString(), JsonElement.class);
    }
    
    /**
     * Send this request and get
     * the response body as a string.
     *
     * @return the response body
     */
    @NonNull
    public String sendAsString() throws IOException, InterruptedException {
        return send(HttpResponse.BodyHandlers.ofString());
    }
    
    /**
     * Send this request and get an
     * input stream as the response.
     *
     * @return the response input stream
     * @see InputStream for input stream
     */
    @NonNull
    public InputStream sendAsInputStream() throws IOException, InterruptedException {
        return send(HttpResponse.BodyHandlers.ofInputStream());
    }
    
    /**
     * Send this request.
     *
     * @param bodyHandler the body handler
     * @param <T>         the type of the response body
     * @return the response body
     * @throws IOException if the request fails or doesn't return 200
     * @see HttpResponse.BodyHandler for body handler
     * @see HttpResponse for response
     */
    @NonNull
    public <T> T send(@NonNull HttpResponse.BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                                 .uri(URI.create(url))
                                                 .method(method, bodyPublisher)
                                                 .timeout(timeout);
        if (headers.keySet().stream().noneMatch("User-Agent"::equalsIgnoreCase)) {
            requestBuilder.header("User-Agent", USER_AGENT);
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) { // Adding headers
            requestBuilder.header(entry.getKey(), entry.getValue());
        }
        HttpResponse<T> response = AntiVPN.HTTP_CLIENT.send(requestBuilder.build(), bodyHandler);
        if (response.statusCode() != 200) { // If the status code is not 200
            if (response.body() instanceof InputStream inputStream) {
                inputStream.close();
            }
            throw new IOException(String.format("Bad status code (%s) returned from %s", response.statusCode(), url));
        }
        return response.body();
    }
}
