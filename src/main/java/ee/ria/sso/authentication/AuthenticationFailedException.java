package ee.ria.sso.authentication;

public class AuthenticationFailedException extends RuntimeException {

    private final String errorMessageKey;

    public AuthenticationFailedException(String errorMessageKey, String message) {
        super(message);
        this.errorMessageKey = errorMessageKey;
    }

    public AuthenticationFailedException(String errorMessageKey, String message, Throwable cause) {
        super(message, cause);
        this.errorMessageKey = errorMessageKey;
    }

    public String getErrorMessageKey() {
        return errorMessageKey;
    }

    public String getErrorMessageKeyOrDefault(String defaultMesageKey) {
        return (errorMessageKey != null) ? errorMessageKey : defaultMesageKey;
    }

}
