package ee.ria.sso.flow.action;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@ConditionalOnProperty("mobile-id.enabled")
@Component
public class MobileIDCheckAuthenticationAction extends AbstractAuthenticationAction {

    private final MobileIDAuthenticationService authenticationService;

    public MobileIDCheckAuthenticationAction(MobileIDAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.checkLoginForMobileID(requestContext);
    }

    @Override
    protected AuthenticationType getAuthenticationType() {
        return AuthenticationType.MobileID;
    }
}
