package ee.ria.sso.service.impl;

import com.codeborne.security.AuthenticationException;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class RiaAuthenticationException extends RuntimeException {

    private AuthenticationException.Code code = AuthenticationException.Code.INTERNAL_ERROR;

    public RiaAuthenticationException(String message) {
        super(message);
    }

    public RiaAuthenticationException(String message, AuthenticationException cause) {
        super(message, cause);
        this.code = cause.getCode();
    }

    public RiaAuthenticationException(String message, Exception cause) {
        super(message, cause);
    }

    public AuthenticationException.Code getCode() {
        return code;
    }

}
