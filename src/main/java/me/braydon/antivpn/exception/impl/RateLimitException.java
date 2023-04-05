package me.braydon.antivpn.exception.impl;

import me.braydon.antivpn.model.APIKey;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * This exception is raised when an
 * {@link APIKey} exceeds a rate limit.
 *
 * @author Braydon
 */
@ResponseStatus(value = HttpStatus.TOO_MANY_REQUESTS, reason = "Rate limit exceeded")
public final class RateLimitException extends APIException {
    public RateLimitException() {
        super(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    }
}
