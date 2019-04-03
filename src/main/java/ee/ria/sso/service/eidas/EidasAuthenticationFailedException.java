package ee.ria.sso.service.eidas;

public class EidasAuthenticationFailedException extends RuntimeException {

    public EidasAuthenticationFailedException(String message) {
        super(message);
    }
}
