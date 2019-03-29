package ee.ria.sso.service;

import lombok.Getter;

@Getter
public class ExternalServiceHasFailedException extends TaraAuthenticationException {

    public ExternalServiceHasFailedException(String errorMessageKey, String exceptionMessage) {
        super(errorMessageKey, exceptionMessage);
    }

    public ExternalServiceHasFailedException(String errorMessageKey, String exceptionMessage, Throwable cause) {
        super(errorMessageKey, exceptionMessage, cause);
    }
}
