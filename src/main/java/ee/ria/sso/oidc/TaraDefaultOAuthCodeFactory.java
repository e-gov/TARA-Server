package ee.ria.sso.oidc;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.ticket.*;
import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.code.OAuthCodeImpl;
import org.apereo.cas.util.DefaultUniqueTicketIdGenerator;
import org.apereo.inspektr.audit.annotation.Audit;

import java.util.Collection;

@Slf4j
@AllArgsConstructor
public class TaraDefaultOAuthCodeFactory implements OAuthCodeFactory {

    /**
     * Default instance for the ticket id generator.
     */
    protected final UniqueTicketIdGenerator oAuthCodeIdGenerator;

    /**
     * ExpirationPolicy for refresh tokens.
     */
    protected final ExpirationPolicy expirationPolicy;

    public TaraDefaultOAuthCodeFactory(final ExpirationPolicy expirationPolicy) {
        this(new DefaultUniqueTicketIdGenerator(), expirationPolicy);
    }

    @Audit(
            action = "OAUTH_CODE",
            actionResolverName = "CREATE_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName = "TARA_CREATE_OAUTH_CODE_RESOURCE_RESOLVER"
    )
    @Override
    public OAuthCode create(final Service service, final Authentication authentication,
                            final TicketGrantingTicket ticketGrantingTicket, final Collection<String> scopes) {
        final String codeId = this.oAuthCodeIdGenerator.getNewTicketId(OAuthCode.PREFIX);
        return new OAuthCodeImpl(codeId, service, authentication,
                this.expirationPolicy, ticketGrantingTicket, scopes);
    }

    @Override
    public TicketFactory get(final Class<? extends Ticket> clazz) {
        return this;
    }
}