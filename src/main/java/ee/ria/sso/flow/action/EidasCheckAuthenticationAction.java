package ee.ria.sso.flow.action;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.eidas.EidasAuthenticationService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@ConditionalOnProperty("eidas.enabled")
@Component("EIDASCheckAuthenticationAction")
public class EidasCheckAuthenticationAction extends AbstractAuthenticationAction {

    private final EidasAuthenticationService authenticationService;

    public EidasCheckAuthenticationAction(EidasAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.checkLoginForEidas(requestContext);
    }

    @Override
    protected AuthenticationType getAuthenticationType() {
        return AuthenticationType.eIDAS;
    }
}
