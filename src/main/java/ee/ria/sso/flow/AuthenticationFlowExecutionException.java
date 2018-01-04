package ee.ria.sso.flow;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.RequestContext;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class AuthenticationFlowExecutionException extends AbstractFlowExecutionException {

    public AuthenticationFlowExecutionException(RequestContext context, Action action, ModelAndView modelAndView, Exception e) {
        super(context, action, modelAndView, e);
    }

}
