package ee.ria.sso.flow.action;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.config.TaraProperties;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.test.MockRequestContext;


public class TaraTicketGrantingTicketCheckActionTest extends AbstractTest {

    public static String MOCK_TGT_ID = "tgt-1234567890abcdefg";

    @Autowired
    CentralAuthenticationService centralAuthenticationService;

    @Autowired
    TaraProperties taraProperties;

    TaraTicketGrantingTicketCheckAction taraTicketGrantingTicketCheckAction;

    MockRequestContext requestContext;

    Ticket mockTicket;

    @Before
    public void setUp() {
        taraTicketGrantingTicketCheckAction = new TaraTicketGrantingTicketCheckAction(centralAuthenticationService, taraProperties);
        requestContext = new MockRequestContext();
        requestContext.getRequestScope().put("ticketGrantingTicketId", MOCK_TGT_ID);

        mockTicket = getValidTicket();
        Mockito.when(centralAuthenticationService.getTicket( Mockito.eq(MOCK_TGT_ID), Mockito.eq(Ticket.class))).thenReturn(mockTicket);
    }

    @Test
    public void isForceOidcAuthenticationRenewalDisabled() {
        Mockito.when(taraProperties.isForceOidcAuthenticationRenewalEnabled()).thenReturn(false);
        Event event = taraTicketGrantingTicketCheckAction.doExecute(requestContext);
        Assert.assertEquals(CasWebflowConstants.TRANSITION_ID_TGT_VALID, event.getId());
    }

    @Test
    public void isForceOidcAuthenticationRenewalEnabled() {
        Mockito.when(taraProperties.isForceOidcAuthenticationRenewalEnabled()).thenReturn(true);
        Event event = taraTicketGrantingTicketCheckAction.doExecute(requestContext);
        Assert.assertEquals(CasWebflowConstants.TRANSITION_ID_TGT_NOT_EXISTS, event.getId());
    }

    private Ticket getValidTicket() {
        Ticket ticket = Mockito.mock(Ticket.class);
        Mockito.when(ticket.isExpired()).thenReturn(false);
        return ticket;
    }
}
