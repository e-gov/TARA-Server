package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.service.AuthenticationService;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
public class MobileIDStartAuthenticationAction extends AbstractAuthenticationAction {

    private final AuthenticationService authenticationService;

    public MobileIDStartAuthenticationAction(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.startLoginByMobileID(requestContext);
    }

}