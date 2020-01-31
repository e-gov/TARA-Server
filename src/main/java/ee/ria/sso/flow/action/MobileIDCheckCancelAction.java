package ee.ria.sso.flow.action;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@ConditionalOnProperty("mobile-id.enabled")
@Component
public class MobileIDCheckCancelAction extends AbstractAuthenticationAction {

    private final MobileIDAuthenticationService authenticationService;

    public MobileIDCheckCancelAction(MobileIDAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return authenticationService.cancelAuthenticationSessionStatusChecking(requestContext);
    }

    @Override
    protected AuthenticationType getAuthenticationType() {
        return AuthenticationType.MobileID;
    }
}
