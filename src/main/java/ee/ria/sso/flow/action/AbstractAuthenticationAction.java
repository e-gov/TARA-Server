package ee.ria.sso.flow.action;

import java.util.Collections;

import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.flow.AuthenticationFlowExecutionException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractAuthenticationAction extends AbstractAction {

    protected abstract Event doAuthenticationExecute(RequestContext requestContext);

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {
        try {
            return this.doAuthenticationExecute(requestContext);
        } catch (Exception e) {
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error",
                Collections.singletonMap("TARA_ERROR_MESSAGE", e.getLocalizedMessage()), HttpStatus.INTERNAL_SERVER_ERROR), e);
        }
    }

}
