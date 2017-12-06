package ee.ria.sso.validators;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class ErrorResponse {

    private String error;

    public ErrorResponse(String error) {
        this.error = error;
    }

    /*
     * ACCESSORS
     */

    public String getError() {
        return error;
    }

}
