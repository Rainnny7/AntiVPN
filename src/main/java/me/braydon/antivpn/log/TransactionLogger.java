package me.braydon.antivpn.log;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import me.braydon.antivpn.metrics.MetricService;
import me.braydon.antivpn.metrics.impl.RequestTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    
    @Autowired
    public TransactionLogger(@NonNull MetricService metrics) {
        this.metrics = metrics;
    }
    
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }
    
    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest rawRequest,
                                  ServerHttpResponse rawResponse) {
        HttpServletRequest request = ((ServletServerHttpRequest) rawRequest).getServletRequest();
        HttpServletResponse response = ((ServletServerHttpResponse) rawResponse).getServletResponse();
        metrics.getTracker(RequestTracker.class).submitRequest(); // Metrics
        
        // Get the request ip ip
        String ip = request.getRemoteAddr();
        String cfAddress = request.getHeader("CF-Connecting-IP");
        if (cfAddress != null) { // Use the CloudFlare ip if present in the request
            ip = cfAddress;
        }
        
        // Getting params
        Map<String, String> params = new HashMap<>();
        for (Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            params.put(entry.getKey(), Arrays.toString(entry.getValue()));
        }
        
        // Getting headers
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        
        // Log the request
        log.info(String.format("[Req] %s | %s | '%s', params=%s, headers=%s",
            request.getMethod(),
            ip,
            request.getRequestURI(),
            params,
            headers
        ));
        
        // Getting response headers
        headers = new HashMap<>();
        for (String headerName : response.getHeaderNames()) {
            headers.put(headerName, response.getHeader(headerName));
        }
        
        // Log the response
        log.info(String.format("[Res] %s, headers=%s",
            response.getStatus(),
            headers
        ));
        return body;
    }
}