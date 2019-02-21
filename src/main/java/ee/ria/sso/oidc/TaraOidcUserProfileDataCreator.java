package ee.ria.sso.oidc;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.support.oauth.profile.OAuth20UserProfileDataCreator;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.inspektr.audit.annotation.Audit;
import org.pac4j.core.context.J2EContext;
import org.springframework.util.Assert;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;



@Slf4j
public class TaraOidcUserProfileDataCreator implements OAuth20UserProfileDataCreator {

    @Override
    @Audit(action = "OAUTH2_USER_PROFILE_DATA",
            actionResolverName = "OAUTH2_USER_PROFILE_DATA_ACTION_RESOLVER",
            resourceResolverName = "OAUTH2_USER_PROFILE_DATA_RESOURCE_RESOLVER")
    public Map<String, Object> createFrom(final AccessToken accessToken, final J2EContext context) {
        Principal principal = getTaraPrincipal(accessToken);

        final Map<String, Object> map = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : principal.getAttributes().entrySet()) {
            map.put(entry.getKey(), entry.getValue());
        }

        map.put(OidcConstants.CLAIM_AUTH_TIME, accessToken.getTicketGrantingTicket().getAuthentication().getAuthenticationDate().toEpochSecond());

        return map;
    }

    private Principal getTaraPrincipal(AccessToken accessToken) {
        TicketGrantingTicket tgt = accessToken.getTicketGrantingTicket();
        Assert.notNull(tgt, "TGT associated with access token cannot be null!");
        final Principal principal = tgt.getAuthentication().getPrincipal();
        log.debug("Preparing user profile response basTaraOidcUserProfileDataCreatorTested on CAS principal [{}]", principal);

        Map<String, Object> attributes = principal.getAttributes()
                .entrySet()
                .stream()
                .filter(
                    entry -> entry.getValue() instanceof List
                    && !((List)entry.getValue()).isEmpty()
                ).collect(
                    Collectors.toMap(
                        entry -> entry.getKey().toLowerCase(),
                        entry -> ((List)entry.getValue()).stream().findFirst().get()
                    )
                );
        return new DefaultPrincipalFactory().createPrincipal(principal.getId(), attributes);
    }
}

