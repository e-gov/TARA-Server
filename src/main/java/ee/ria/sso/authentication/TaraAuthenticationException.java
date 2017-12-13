package ee.ria.sso.authentication;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class TaraAuthenticationException extends RuntimeException {

    public TaraAuthenticationException(String message) {
        super(message);
    }

    public TaraAuthenticationException(String message, Exception cause) {
        super(message, cause);
    }

}
