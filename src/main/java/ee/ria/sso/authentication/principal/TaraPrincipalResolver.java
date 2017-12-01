package ee.ria.sso.authentication.principal;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.stereotype.Component;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
public class TaraPrincipalResolver implements PrincipalResolver {

    public Principal resolve(Credential credential, Principal principal, AuthenticationHandler handler) {
        return principal;
    }

    public boolean supports(Credential credential) {
        return StringUtils.isNotBlank(credential.getId());
    }

    public String toString() {
        return (new ToStringBuilder(this)).toString();
    }

    public IPersonAttributeDao getAttributeRepository() {
        return null;
    }

}
