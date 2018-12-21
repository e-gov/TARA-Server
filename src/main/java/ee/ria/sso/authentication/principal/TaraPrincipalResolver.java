package ee.ria.sso.authentication.principal;

import ee.ria.sso.authentication.credential.TaraCredential;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
public class TaraPrincipalResolver implements PrincipalResolver {

    public Principal resolve(Credential credential, Optional<Principal> principal, Optional<AuthenticationHandler> handler) {
        return principal.isPresent() ? principal.get() : null;
    }

    public boolean supports(Credential credentials) {
        return TaraCredential.class.isAssignableFrom(credentials.getClass());
    }

    public String toString() {
        return (new ToStringBuilder(this)).toString();
    }

    public IPersonAttributeDao getAttributeRepository() {
        return null;
    }

}
