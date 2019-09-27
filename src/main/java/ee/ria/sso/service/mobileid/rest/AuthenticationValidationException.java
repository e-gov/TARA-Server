package ee.ria.sso.service.mobileid.rest;

class AuthenticationValidationException extends RuntimeException {

    public AuthenticationValidationException(String message) {
        super(message);
    }
}
