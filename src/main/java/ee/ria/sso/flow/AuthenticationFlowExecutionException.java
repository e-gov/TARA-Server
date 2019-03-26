package ee.ria.sso.flow;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.ActionExecutionException;
import org.springframework.webflow.execution.RequestContext;

@Getter
public class AuthenticationFlowExecutionException extends ActionExecutionException {

    private final String localizedMessage;
    private final HttpStatus httpStatusCode;

    public AuthenticationFlowExecutionException(RequestContext context, Action action, HttpStatus httpStatusCode, String localizedMessage, Exception e) {
        super(context.getActiveFlow().getId(), context.getCurrentState() != null ? context.getCurrentState().getId() : null, action, context.getAttributes(), e);
        this.httpStatusCode = httpStatusCode;
        this.localizedMessage = localizedMessage;
    }

    public static AuthenticationFlowExecutionException ofUnauthorized(RequestContext context, Action action, String localizedMessage) {
        return new AuthenticationFlowExecutionException(context, action, HttpStatus.UNAUTHORIZED, localizedMessage, null);
    }

    public static AuthenticationFlowExecutionException ofUnauthorized(RequestContext context, Action action, String localizedMessage, Exception e) {
        return new AuthenticationFlowExecutionException(context, action, HttpStatus.UNAUTHORIZED, localizedMessage, e);
    }

    public static AuthenticationFlowExecutionException ofServiceUnavailable(RequestContext context, Action action, String localizedMessage, Exception e) {
        return new AuthenticationFlowExecutionException(context, action, HttpStatus.SERVICE_UNAVAILABLE, localizedMessage, e);
    }

    public static AuthenticationFlowExecutionException ofInternalServerError(RequestContext context, Action action, String localizedMessage, Exception e) {
        return new AuthenticationFlowExecutionException(context, action, HttpStatus.INTERNAL_SERVER_ERROR, localizedMessage, e);
    }
}
