package ee.ria.sso.flow.action;

import ee.ria.sso.service.banklink.BanklinkAuthenticationService;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Component("BankCheckAuthenticationAction")
public class BankCheckAuthenticationAction extends AbstractAuthenticationAction {

    private final BanklinkAuthenticationService authenticationService;

    public BankCheckAuthenticationAction(BanklinkAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    protected Event doAuthenticationExecute(RequestContext requestContext) {
        return this.authenticationService.checkLoginForBankLink(requestContext);
    }
}
