package ee.ria.sso.authentication;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class TaraAuthenticationException extends RuntimeException {

    private String localizedErrorMessage;

    public TaraAuthenticationException(String localizedErrorMessage, Exception cause) {
        super(cause);
        this.localizedErrorMessage = localizedErrorMessage;
    }

    @Override
    public String getLocalizedMessage() {
        return this.localizedErrorMessage;
    }

}
