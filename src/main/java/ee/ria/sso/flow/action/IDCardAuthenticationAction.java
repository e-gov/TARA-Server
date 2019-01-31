package ee.ria.sso.flow.action;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.idcard.IDCardAuthenticationService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@ConditionalOnProperty("id-card.enabled")
@Component("idCardAuthenticationAction")
public class IDCardAuthenticationAction extends AbstractAuthenticationAction {

    private final IDCardAuthenticationService authenticationService;

    public IDCardAuthenticationAction(IDCardAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.loginByIDCard(requestContext);
    }

    @Override
    protected AuthenticationType getAuthenticationType() {
        return AuthenticationType.IDCard;
    }
}
