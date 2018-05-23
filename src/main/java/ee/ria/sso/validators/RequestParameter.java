package ee.ria.sso.validators;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum RequestParameter {

    CLIENT_ID("invalid_client", true),
    SCOPE("invalid_scope", true),
    STATE("invalid_request", true),
    REDIRECT_URI("invalid_request", true),
    RESPONSE_TYPE("invalid_request", true),
    NONCE("invalid_request", false),
    ACR_VALUES("invalid_request", false);

    private String error;
    private boolean mandatory;

    RequestParameter(String error, boolean mandatory) {
        this.error = error;
        this.mandatory = mandatory;
    }

    public String getParameterKey() {
        return this.name().toLowerCase();
    }

    /*
     * ACCESSORS
     */

    public String getError() {
        return error;
    }

    public boolean isMandatory() {
        return mandatory;
    }

}
