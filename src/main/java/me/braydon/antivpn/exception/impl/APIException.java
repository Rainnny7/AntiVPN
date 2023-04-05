package me.braydon.antivpn.exception.impl;

import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.http.HttpStatus;

/**
 * A standard runtime exception
 * which holds a status code.
 *
 * @author Braydon
 * @see HttpStatus for status code
 */
@Getter @ToString
public class APIException extends RuntimeException {
    /**
     * The {@link HttpStatus} of this error.
     */
    @NonNull private final HttpStatus status;
    
    /**
     * Create a new API exception.
     *
     * @param status  the status code
     * @param message the message
     * @see HttpStatus for status code
     */
    public APIException(@NonNull HttpStatus status, @NonNull String message) {
        super(message);
        this.status = status;
    }
    
    /**
     * Create a new API exception.
     *
     * @param status    the status code
     * @param exception the exception
     * @see HttpStatus for status code
     */
    public APIException(@NonNull HttpStatus status, @NonNull Exception exception) {
        super(exception);
        this.status = status;
    }
}