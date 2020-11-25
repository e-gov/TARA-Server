package ee.ria.sso.flow.action;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.cas.CasConfigProperties;
import ee.ria.sso.flow.AuthenticationFlowExecutionException;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.manager.ManagerService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.AbstractRegisteredService;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.web.support.WebUtils;
import org.pac4j.core.context.Pac4jConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;

import static ee.ria.sso.Constants.CAS_SERVICE_ATTRIBUTE_NAME;

@Slf4j
@NoArgsConstructor
@AllArgsConstructor
public abstract class AbstractAuthenticationAction extends AbstractAction {

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @Autowired
    private ThymeleafSupport thymeleafSupport;

    @Autowired
    private CasConfigProperties casConfigProperties;

    @Autowired
    private ManagerService managerService;

    protected abstract Event doAuthenticationExecute(RequestContext requestContext) throws IOException, CertificateException;

    protected abstract AuthenticationType getAuthenticationType();

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {

        WebApplicationService service = getWebApplicationService(requestContext);
        assertValidClient(requestContext, service);
        assertSessionNotExpiredAndAuthMethodAllowed(requestContext, service);

        try {
            return this.doAuthenticationExecute(requestContext);
        } catch (UserAuthenticationFailedException e) {
            log.warn("Authentication failed: " + e.getMessage(), e);
            String localizedMessage = messageSource.getMessage(e.getErrorMessageKey());
            clearFlowScope(requestContext);
            throw AuthenticationFlowExecutionException.ofUnauthorized(requestContext, this, localizedMessage, e);
        } catch (ExternalServiceHasFailedException e) {
            log.error("External service has failed: " + e.getMessage(), e);
            String localizedMessage = messageSource.getMessage(e.getErrorMessageKey());
            clearFlowScope(requestContext);
            throw AuthenticationFlowExecutionException.ofServiceUnavailable(requestContext, this, localizedMessage, e);
        } catch (Exception e) {
            log.error("Unexpected technical error: " + e.getMessage(), e);
            String localizedMessage = messageSource.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR);
            clearFlowScope(requestContext);
            throw AuthenticationFlowExecutionException.ofInternalServerError(requestContext, this, localizedMessage, e);
        }
    }

    private void assertValidClient(RequestContext requestContext, WebApplicationService service) {
        if (service == null) {
            log.error("Callback failed! No service parameter found in flow of session! Possible causes: either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
            throw AuthenticationFlowExecutionException.ofUnauthorized(requestContext, this, messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED));
        }

        if (!isOauth2Client(service) && !isCASClient(service.getOriginalUrl())) {
            log.error("Invalid client_name! Possible cause: client_name parameter has been changed in URL");
            throw AuthenticationFlowExecutionException.ofUnauthorized(requestContext, this, messageSource.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR));
        }
    }

    private boolean isCASClient(String serviceUrl) {
        Optional<List<AbstractRegisteredService>> abstractRegisteredServices = managerService.getAllAbstractRegisteredServices();
        if (abstractRegisteredServices.isPresent()) {
            for (AbstractRegisteredService ars: abstractRegisteredServices.get()) {
                if (serviceUrl.matches(ars.getServiceId())) {
                    return true;
                }
            }
        }
        return false;
    }

    private void assertSessionNotExpiredAndAuthMethodAllowed(RequestContext requestContext, WebApplicationService service) {
        if (isOauth2Client(service)) {
            if (!requestContext.getExternalContext().getSessionMap().contains(Pac4jConstants.REQUESTED_URL)) {
                log.error("Oauth callback url not found in session! Possible causes: either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
                throw AuthenticationFlowExecutionException.ofUnauthorized(requestContext, this, messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED));
            } else if (!thymeleafSupport.isAuthMethodAllowed(getAuthenticationType())) {
                log.error("This authentication method usage was not initially specified by the scope parameter when the authentication process was initialized!");
                throw AuthenticationFlowExecutionException.ofUnauthorized(requestContext, this, messageSource.getMessage(Constants.MESSAGE_KEY_AUTH_METHOD_RESTRICTED_BY_SCOPE));
            }
        }
    }

    private boolean isOauth2Client(WebApplicationService service) {
        String clientName = getParameterValueFromUrl(service.getOriginalUrl(), "client_name");
        return clientName != null && clientName.equals(Authenticators.CAS_OAUTH_CLIENT);
    }

    private WebApplicationService getWebApplicationService(RequestContext requestContext) {
        WebApplicationService service = WebUtils.getService(requestContext);

        if (service != null) {
            return service;
        } else if (requestContext.getExternalContext().getSessionMap().contains(CAS_SERVICE_ATTRIBUTE_NAME)
                && requestContext.getExternalContext().getSessionMap().get(CAS_SERVICE_ATTRIBUTE_NAME) instanceof WebApplicationService) {
            return (WebApplicationService) requestContext.getExternalContext().getSessionMap().get(CAS_SERVICE_ATTRIBUTE_NAME);
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

    protected static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }
}
