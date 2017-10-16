package ee.ria.sso;


import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;


/**
 * Created by serkp on 14.09.2017.
 */
@Component
@Qualifier(value = "echoingPrincipalResolver")
public class EchoingPrincipalResolver implements PrincipalResolver {
    public EchoingPrincipalResolver() {
    }

    public Principal resolve(Credential credential, Principal principal,
                             AuthenticationHandler handler) {
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
