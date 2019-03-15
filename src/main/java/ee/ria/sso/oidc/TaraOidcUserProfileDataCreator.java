package ee.ria.sso.oidc;

import ee.ria.sso.authentication.principal.TaraPrincipalFactory;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.support.oauth.profile.OAuth20UserProfileDataCreator;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.inspektr.audit.annotation.Audit;
import org.pac4j.core.context.J2EContext;

import java.util.LinkedHashMap;
import java.util.Map;



@Slf4j
public class TaraOidcUserProfileDataCreator implements OAuth20UserProfileDataCreator {

    @Override
    @Audit(action = "USER_INFO_DATA",
            actionResolverName = "OAUTH2_USER_PROFILE_DATA_ACTION_RESOLVER",
            resourceResolverName = "TARA_USER_INFO_DATA_RESOURCE_RESOLVER")
    public Map<String, Object> createFrom(final AccessToken accessToken, final J2EContext context) {

        Principal principal = TaraPrincipalFactory.createPrincipal(accessToken.getTicketGrantingTicket());

        final Map<String, Object> map = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : principal.getAttributes().entrySet()) {
            map.put(entry.getKey(), entry.getValue());
        }

        map.put(OidcConstants.CLAIM_AUTH_TIME, accessToken.getTicketGrantingTicket().getAuthentication().getAuthenticationDate().toEpochSecond());

        return map;
    }
}

