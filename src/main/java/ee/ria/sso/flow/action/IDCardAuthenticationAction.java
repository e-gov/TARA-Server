package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.service.AuthenticationService;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component("idCardAuthenticationAction")
public class IDCardAuthenticationAction extends AbstractAuthenticationAction {

    private final AuthenticationService authenticationService;

    public IDCardAuthenticationAction(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.loginByIDCard(requestContext);
    }

}
