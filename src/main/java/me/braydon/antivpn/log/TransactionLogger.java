package me.braydon.antivpn.log;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.common.ClientIpResolver;
import me.braydon.antivpn.metric.MetricService;
import me.braydon.antivpn.metric.impl.RequestTracker;
import me.braydon.antivpn.model.APIKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Responsible for logging request and
 * response transactions to the terminal.
 *
 * @author Braydon
 * @see HttpServletRequest for request
 * @see HttpServletResponse for response
 */
@ControllerAdvice
@Slf4j(topic = "Req/Res Transaction")
public class TransactionLogger implements ResponseBodyAdvice<Object> {
    @NonNull private final MetricService metrics;
    @NonNull private final ClientIpResolver clientIpResolver;
    
    /**
     * The header API keys are sent in, masked in logs.
     */
    @Value("${auth.header:X-API-Key}")
    private String authHeader;
    
    public TransactionLogger(@NonNull MetricService metrics, @NonNull ClientIpResolver clientIpResolver) {
        this.metrics = metrics;
        this.clientIpResolver = clientIpResolver;
    }
    
    @Override
    public boolean supports(@NonNull MethodParameter returnType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }
    
    @Override
    public Object beforeBodyWrite(Object body, @NonNull MethodParameter returnType, @NonNull MediaType selectedContentType,
                                  @NonNull Class<? extends HttpMessageConverter<?>> selectedConverterType, @NonNull ServerHttpRequest rawRequest,
                                  @NonNull ServerHttpResponse rawResponse) {
        if (!(rawRequest instanceof ServletServerHttpRequest servletRequest) || !(rawResponse instanceof ServletServerHttpResponse servletResponse)) {
            return body;
        }
        HttpServletRequest request = servletRequest.getServletRequest();
        HttpServletResponse response = servletResponse.getServletResponse();
        metrics.getTracker(RequestTracker.class).submitRequest(); // Metrics
        
        // Getting params
        Map<String, String> params = new HashMap<>();
        for (Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            params.put(entry.getKey(), Arrays.toString(entry.getValue()));
        }
        log.info("[Req] {} | {} | '{}', params={}", request.getMethod(), clientIpResolver.resolve(request), request.getRequestURI(), params);
        
        if (log.isDebugEnabled()) {
            // Getting headers
            Map<String, String> headers = new HashMap<>();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                String value = request.getHeader(headerName);
                headers.put(headerName, headerName.equalsIgnoreCase(authHeader) ? APIKey.mask(value) : value);
            }
            log.debug("[Req] headers={}", headers);
            
            // Getting response headers
            Map<String, String> responseHeaders = new HashMap<>();
            for (String headerName : response.getHeaderNames()) {
                responseHeaders.put(headerName, response.getHeader(headerName));
            }
            log.debug("[Res] {}, headers={}", response.getStatus(), responseHeaders);
        }
        return body;
    }
}
