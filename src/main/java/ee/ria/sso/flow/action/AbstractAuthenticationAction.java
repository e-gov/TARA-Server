package ee.ria.sso.flow.action;

import java.util.Collections;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.flow.AuthenticationFlowExecutionException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
@Slf4j
public abstract class AbstractAuthenticationAction extends AbstractAction {

    protected abstract Event doAuthenticationExecute(RequestContext requestContext);

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {
        try {
            return this.doAuthenticationExecute(requestContext);
        } catch (Exception e) {
            log.error("Authentication failed: " + e.getLocalizedMessage(), e);
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error",
                Collections.singletonMap("TARA_ERROR_MESSAGE", e.getLocalizedMessage()), HttpStatus.INTERNAL_SERVER_ERROR), e);
        }
    }

}
