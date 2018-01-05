package ee.ria.sso.authentication;

import org.pac4j.core.exception.CredentialsException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraCredentialsException extends RuntimeException {

    private final String error = "invalid_client";
    private String key;
    private Object value;

    public TaraCredentialsException(String key, Object value) {
        super(String.format("Credential value <%s> is invalid", value));
        this.key = key;
        this.value = value;
    }

    public TaraCredentialsException(String message, CredentialsException e) {
        super(message, e);
    }

    /*
     * ACCESSORS
     */

    public String getError() {
        return error;
    }

    public String getKey() {
        return key;
    }

    public Object getValue() {
        return value;
    }

}
