package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.service.RiaAuthenticationService;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
public class MobileIDCheckAuthenticationAction extends AbstractAction {

    private final RiaAuthenticationService riaAuthenticationService;

    public MobileIDCheckAuthenticationAction(RiaAuthenticationService riaAuthenticationService) {
        this.riaAuthenticationService = riaAuthenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doExecute(RequestContext requestContext) throws Exception {
        return this.riaAuthenticationService.checkLoginForMobileID(requestContext);
    }

}
