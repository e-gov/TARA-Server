package org.apereo.cas.ticket.code;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.util.DefaultUniqueTicketIdGenerator;
import org.apereo.inspektr.audit.annotation.Audit;

public class DefaultOAuthCodeFactory implements OAuthCodeFactory {

    protected final UniqueTicketIdGenerator oAuthCodeIdGenerator;

    protected final ExpirationPolicy expirationPolicy;

    public DefaultOAuthCodeFactory(final ExpirationPolicy expirationPolicy) {
        this(new DefaultUniqueTicketIdGenerator(), expirationPolicy);
    }

    public DefaultOAuthCodeFactory(final UniqueTicketIdGenerator refreshTokenIdGenerator, final ExpirationPolicy expirationPolicy) {
        this.oAuthCodeIdGenerator = refreshTokenIdGenerator;
        this.expirationPolicy = expirationPolicy;
    }

    @Audit(
            action = "OAUTH_CODE",
            actionResolverName = "CREATE_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName = "TARA_CREATE_OAUTH_CODE_RESOURCE_RESOLVER"
    )
    @Override
    public OAuthCode create(final Service service, final Authentication authentication, final TicketGrantingTicket ticketGrantingTicket) {
        final String codeId = this.oAuthCodeIdGenerator.getNewTicketId(OAuthCode.PREFIX);
        return new OAuthCodeImpl(codeId, service, authentication, this.expirationPolicy, ticketGrantingTicket);
    }

    @Override
    public <T extends TicketFactory> T get(final Class<? extends Ticket> clazz) {
        return (T) this;
    }
}
