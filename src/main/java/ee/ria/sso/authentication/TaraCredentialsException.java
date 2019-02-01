package ee.ria.sso.authentication;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraCredentialsException extends RuntimeException {

    private final String key;

    public TaraCredentialsException(String key, String value) {
        super(String.format("Credential value <%s> is invalid", value));
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
