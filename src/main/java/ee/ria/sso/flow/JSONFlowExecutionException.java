package ee.ria.sso.flow;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class JSONFlowExecutionException extends AbstractFlowExecutionException {

    private JSONFlowExecutionException(ModelAndView modelAndView, Exception e) {
        super("pseudo-json-view-id", modelAndView, e);
    }

    public static JSONFlowExecutionException ofUnauthorized(Map<String, ?> model, Exception e) {
        ModelAndView modelAndView = new ModelAndView(new MappingJackson2JsonView(), model);
        modelAndView.setStatus(HttpStatus.UNAUTHORIZED);
        return new JSONFlowExecutionException(modelAndView, e);
    }

    public static JSONFlowExecutionException ofBadRequest(Map<String, ?> model, Exception e) {
        ModelAndView modelAndView = new ModelAndView(new MappingJackson2JsonView(), model);
        modelAndView.setStatus(HttpStatus.BAD_REQUEST);
        return new JSONFlowExecutionException(modelAndView, e);
    }

}
