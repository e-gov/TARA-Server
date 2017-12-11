package ee.ria.sso.authentication;

import org.pac4j.core.exception.CredentialsException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraCredentialsException extends RuntimeException {

    private String error = "invalid_client";

    public TaraCredentialsException(String message, CredentialsException e) {
        super(message, e);
    }

    /*
     * ACCESSORS
     */

    public String getError() {
        return error;
    }

}
