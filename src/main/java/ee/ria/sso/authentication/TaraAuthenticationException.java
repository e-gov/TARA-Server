package ee.ria.sso.authentication;

import com.codeborne.security.AuthenticationException;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class TaraAuthenticationException extends RuntimeException {

    private AuthenticationException.Code code = AuthenticationException.Code.INTERNAL_ERROR;

    public TaraAuthenticationException(String message) {
        super(message);
    }

    public TaraAuthenticationException(String message, AuthenticationException cause) {
        super(message, cause);
        this.code = cause.getCode();
    }

    public TaraAuthenticationException(String message, Exception cause) {
        super(message, cause);
    }

    public AuthenticationException.Code getCode() {
        return code;
    }

}
