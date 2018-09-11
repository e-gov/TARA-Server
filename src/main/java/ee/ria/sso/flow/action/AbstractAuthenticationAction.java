package ee.ria.sso.flow.action;

import java.util.Collections;

import ee.ria.sso.Constants;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import lombok.extern.slf4j.Slf4j;
import org.pac4j.core.context.Pac4jConstants;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    protected abstract Event doAuthenticationExecute(RequestContext requestContext);

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {

        if (!requestContext.getExternalContext().getSessionMap().contains(Pac4jConstants.REQUESTED_URL)) {
            log.error("Authentication failed: the originally requested url was not found in session! Possible causes: either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error",
                    Collections.singletonMap(Constants.ERROR_MESSAGE, messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)), HttpStatus.UNAUTHORIZED), null);
        }

        try {
            return this.doAuthenticationExecute(requestContext);
        } catch (Exception e) {
            log.error("Authentication failed: " + e.getLocalizedMessage(), e);
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error",
                Collections.singletonMap(Constants.ERROR_MESSAGE, e.getLocalizedMessage()), HttpStatus.INTERNAL_SERVER_ERROR), e);
        }
    }
}
