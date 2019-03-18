package ee.ria.sso.authentication;

import lombok.Getter;

@Getter
public class AuthenticationFailedException extends RuntimeException {

    private final String errorMessageKey;

    public AuthenticationFailedException(String errorMessageKey, String exceptionMessage) {
        super(exceptionMessage);
        this.errorMessageKey = errorMessageKey;
    }

    public AuthenticationFailedException(String errorMessageKey, String exceptionMessage, Throwable cause) {
        super(exceptionMessage, cause);
        this.errorMessageKey = errorMessageKey;
    }
}
