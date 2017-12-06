package ee.ria.sso.validators;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.J2EContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class ErrorResponse {

    private final Logger log = LoggerFactory.getLogger(ErrorResponse.class);
    private final J2EContext context;
    private String error = "invalid_request";
    private String errorDescription;

    private ErrorResponse(J2EContext context) {
        this.context = context;
    }

    public static ErrorResponse of(J2EContext context, String error, String errorDescription) {
        ErrorResponse response = new ErrorResponse(context);
        response.error = error;
        response.errorDescription = errorDescription;
        return response;
    }

    public static ErrorResponse of(J2EContext context, String message) {
        ErrorResponse response = new ErrorResponse(context);
        response.errorDescription = message;
        return response;
    }

    public boolean isValidRedirectURI() {
        try {
            new URI(this.context.getRequestParameter(RequestParameter.REDIRECT_URI.name().toLowerCase()));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean hasErrorDescription() {
        return StringUtils.isNotBlank(this.errorDescription);
    }

    public boolean sendRedirect() {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(this.context.getRequestParameter(RequestParameter.REDIRECT_URI.name().toLowerCase()));
            sb.append("?");
            try {
                sb.append(String.format("error=%s", URLEncoder.encode(this.error, "UTF-8")));
            } catch (UnsupportedEncodingException e) {
                sb.append(String.format("error=server%3Derror"));
            }
            if (this.hasErrorDescription()) {
                sb.append(String.format("&error_description=%s", URLEncoder.encode(this.errorDescription, "UTF-8")));
            }
            String state = this.context.getRequestParameter(RequestParameter.STATE.name().toLowerCase());
            if (StringUtils.isNotBlank(state)) {
                sb.append(String.format("&state=%s", state));
            }
            this.context.getResponse().sendRedirect(sb.toString());
            return true;
        } catch (Exception e) {
            if (this.log.isDebugEnabled()) {
                this.log.error("Error while redirecting error response", e);
            } else {
                this.log.error("Error while redirecting error response: {}", e.getMessage());
            }
            return false;
        }
    }

    /*
     * ACCESSORS
     */

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

}
