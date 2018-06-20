package ee.ria.sso.flow.action;

import ee.ria.sso.service.banklink.BanklinkAuthenticationService;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Component("BankStartAuthenticationAction")
public class BankStartAuthenticationAction extends AbstractAuthenticationAction {

    private final BanklinkAuthenticationService authenticationService;

    public BankStartAuthenticationAction(BanklinkAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.startLoginByBankLink(requestContext);
    }
}