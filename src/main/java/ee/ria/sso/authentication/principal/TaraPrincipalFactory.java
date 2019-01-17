package ee.ria.sso.authentication.principal;

import java.util.Map;

import lombok.EqualsAndHashCode;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
@EqualsAndHashCode
public class TaraPrincipalFactory implements PrincipalFactory {

    private static final long serialVersionUID = 1L;

    public TaraPrincipalFactory() {
    }

    public Principal createPrincipal(String id) {
        throw new IllegalArgumentException("Attributes are mandatory when creating principal");
    }

    public Principal createPrincipal(String id, Map<String, Object> attributes) {
        if (MapUtils.isEmpty(attributes)) {
            throw new IllegalArgumentException("No attributes found when creating principal");
        }
        return new TaraPrincipal(id, attributes);
    }
}
