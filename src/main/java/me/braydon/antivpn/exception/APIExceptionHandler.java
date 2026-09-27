package me.braydon.antivpn.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import me.braydon.antivpn.exception.impl.APIException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.Map;

/**
 * Turns exceptions thrown by controllers into JSON error responses.
 *
 * @author Braydon
 */
@RestControllerAdvice
public class APIExceptionHandler {
    @ExceptionHandler(APIException.class)
    public ResponseEntity<Map<String, Object>> handle(@NonNull APIException ex, @NonNull HttpServletRequest request) {
        return respond(ex.getStatus(), ex.getCause() == null ? ex.getMessage() : ex.getCause().getMessage(), request);
    }
    
    @ExceptionHandler({ MissingServletRequestParameterException.class, MethodArgumentTypeMismatchException.class })
    public ResponseEntity<Map<String, Object>> handleBadRequest(@NonNull Exception ex, @NonNull HttpServletRequest request) {
        String message = ex instanceof MethodArgumentTypeMismatchException mismatch
                             ? "Invalid value for parameter '" + mismatch.getName() + "'"
                             : ex.getMessage();
        return respond(HttpStatus.BAD_REQUEST, message, request);
    }
    
    @NonNull
    private static ResponseEntity<Map<String, Object>> respond(@NonNull HttpStatus status, String message, @NonNull HttpServletRequest request) {
        return ResponseEntity.status(status).body(ErrorResponses.body(status, message, request.getRequestURI()));
    }
}
