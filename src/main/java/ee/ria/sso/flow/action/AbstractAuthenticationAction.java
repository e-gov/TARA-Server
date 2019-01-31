package ee.ria.sso.flow.action;

import java.util.Collections;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.ThymeleafSupport;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.web.support.WebUtils;
import org.pac4j.core.context.Pac4jConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.flow.AuthenticationFlowExecutionException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
@Slf4j
@NoArgsConstructor
@AllArgsConstructor
public abstract class AbstractAuthenticationAction extends AbstractAction {

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @Autowired
    private ThymeleafSupport thymeleafSupport;

    protected abstract Event doAuthenticationExecute(RequestContext requestContext);

    protected abstract AuthenticationType getAuthenticationType();

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {

        assertSessionNotExpiredAndAuthMethodAllowed(requestContext);

        try {
            return this.doAuthenticationExecute(requestContext);
        } catch (Exception e) {
            log.error("Authentication failed: " + e.getLocalizedMessage(), e);
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error",
                Collections.singletonMap(Constants.ERROR_MESSAGE, e.getLocalizedMessage()), HttpStatus.INTERNAL_SERVER_ERROR), e);
        }
    }


    private void assertSessionNotExpiredAndAuthMethodAllowed(RequestContext requestContext) {
        WebApplicationService service = getWebApplicationService(requestContext);
        if (service == null) {
            log.error("Callback failed! No service parameter found in flow of session! Possible causes: either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error", Collections.singletonMap(Constants.ERROR_MESSAGE, messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)), HttpStatus.UNAUTHORIZED), null);
        } else if (isOauth2Client(service) && !requestContext.getExternalContext().getSessionMap().contains(Pac4jConstants.REQUESTED_URL)) {
            log.error("Oauth callback url not found in session! Possible causes: either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error", Collections.singletonMap(Constants.ERROR_MESSAGE, messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)), HttpStatus.UNAUTHORIZED), null);
        }

        if (isOauth2Client(service) && !thymeleafSupport.isAuthMethodAllowed(getAuthenticationType())) {
            log.error("This authentication method usage was not initially specified by the scope parameter when the authentication process was initialized!");
            throw new AuthenticationFlowExecutionException(requestContext, this, new ModelAndView("error", Collections.singletonMap(Constants.ERROR_MESSAGE, messageSource.getMessage(Constants.MESSAGE_KEY_AUTH_METHOD_RESTRICTED_BY_SCOPE)), HttpStatus.UNAUTHORIZED), null);
        }
    }

    private boolean isOauth2Client(WebApplicationService service) {
        Assert.notNull(service, "service paramater cannot be null!");
        String clientName = getParameterValueFromUrl(service.getOriginalUrl(), "client_name");
        return clientName != null && clientName.equals(Authenticators.CAS_OAUTH_CLIENT);
    }

    private WebApplicationService getWebApplicationService(RequestContext requestContext) {
        WebApplicationService service = WebUtils.getService(requestContext);

        if (service != null) {
            return service;
        } else if (service == null && requestContext.getExternalContext().getSessionMap().contains("service") && requestContext.getExternalContext().getSessionMap().get("service") instanceof WebApplicationService) {
            return (WebApplicationService) requestContext.getExternalContext().getSessionMap().get("service");
        } else {
            return null;
        }
    }

    private String getParameterValueFromUrl(String serviceParameter, String parameterName) {
        try {
            return UriComponentsBuilder.fromUriString(serviceParameter).build().getQueryParams().getFirst(parameterName);
        } catch (Exception e) {
            log.warn("Failed to get " + parameterName + " from url: " + e.getMessage());
            return null;
        }
    }
}
