package ee.ria.sso.validators;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum RequestParameter {

    CLIENT_ID("invalid_client"),
    SCOPE("invalid_scope"),
    STATE("invalid_request"),
    REDIRECT_URI("invalid_request"),
    RESPONSE_TYPE("invalid_request");

    private String error;

    RequestParameter(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }

}
