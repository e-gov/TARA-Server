package ee.ria.sso.flow.action;

import ee.ria.sso.config.TaraProperties;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.login.TicketGrantingTicketCheckAction;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
@Component
public class TaraTicketGrantingTicketCheckAction extends TicketGrantingTicketCheckAction {

    private TaraProperties taraProperties;

    public TaraTicketGrantingTicketCheckAction(CentralAuthenticationService centralAuthenticationService, TaraProperties taraProperties) {
        super(centralAuthenticationService);
        this.taraProperties = taraProperties;
    }

    /**
     * Determines whether the TGT in the flow request context is valid.
     *
     * @param requestContext Flow request context.
     * @return webflow transition to indicate TGT status.
     */
    @Override
    public Event doExecute(final RequestContext requestContext) {
        if (taraProperties.isForceOidcAuthenticationRenewalEnabled()) {
            return new Event(this, CasWebflowConstants.TRANSITION_ID_TGT_NOT_EXISTS);
        } else {
            return super.doExecute(requestContext);
        }
    }
}
