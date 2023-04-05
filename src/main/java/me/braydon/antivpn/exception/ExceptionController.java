package me.braydon.antivpn.exception;

import lombok.NonNull;
import me.braydon.antivpn.AntiVPN;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author Braydon
 */
@Controller
@RequestMapping("/error")
public final class ExceptionController extends AbstractErrorController {
    public ExceptionController(@NonNull ErrorAttributes errorAttributes) {
        super(errorAttributes);
    }
    
    @RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> error(@NonNull HttpServletRequest request) {
        Map<String, Object> body = getErrorAttributes(request, ErrorAttributeOptions.of(
            AntiVPN.isDevelopment() ? ErrorAttributeOptions.Include.values() : new ErrorAttributeOptions.Include[] {
                ErrorAttributeOptions.Include.MESSAGE
            }
        ));
        HttpStatus status = getStatus(request); // The status code
        return new ResponseEntity<>(body, status);
    }
}