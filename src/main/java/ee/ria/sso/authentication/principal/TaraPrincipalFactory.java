package ee.ria.sso.authentication.principal;

import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.springframework.util.Assert;

import java.util.Map;

@NoArgsConstructor
@EqualsAndHashCode
public class TaraPrincipalFactory implements PrincipalFactory {

    private static final long serialVersionUID = 1L;

    @Override
    public Principal createPrincipal(String id) {
        throw new IllegalArgumentException("Attributes are mandatory when creating principal");
    }

    public Principal createPrincipal(String id, Map<String, Object> attributes) {
        Assert.notEmpty(attributes, "No attributes found when creating principal");
        return new TaraPrincipal(id, attributes);
    }
}
