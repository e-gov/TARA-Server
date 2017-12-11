package ee.ria.sso.flow;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class JSONFlowExecutionException extends AbstractFlowExecutionException {

    private JSONFlowExecutionException(Map<String, ?> model, HttpStatus status, Exception e) {
        super(new MappingJackson2JsonView(), model, status, e);
    }

    public static JSONFlowExecutionException ofUnauthorized(Map<String, ?> model, Exception e) {
        return new JSONFlowExecutionException(model, HttpStatus.UNAUTHORIZED, e);
    }

    public static JSONFlowExecutionException ofBadRequest(Map<String, ?> model, Exception e) {
        return new JSONFlowExecutionException(model, HttpStatus.BAD_REQUEST, e);
    }

}
