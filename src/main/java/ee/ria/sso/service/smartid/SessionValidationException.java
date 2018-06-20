package ee.ria.sso.service.smartid;

import ee.sk.smartid.exception.SmartIdException;
import lombok.Getter;

@Getter
class SessionValidationException extends SmartIdException {

    private final String errorMessageKey;

    public SessionValidationException(String message, String errorMessageKey) {
        super(message);
        this.errorMessageKey = errorMessageKey;
    }
}
