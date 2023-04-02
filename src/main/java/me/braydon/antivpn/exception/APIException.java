package me.braydon.antivpn.exception;

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
     * Constructs a new runtime exception with the specified detail message.
     * The cause is not initialized, and may subsequently be initialized by a
     * call to {@link #initCause}.
     *
     * @param status  the status code
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     */
    public APIException(@NonNull HttpStatus status, @NonNull String message) {
        super(message);
        this.status = status;
    }
}