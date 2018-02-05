package ee.ria.sso.authentication.principal;

import java.util.Map;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;

import ee.ria.sso.authentication.TaraAuthenticationException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraPrincipalFactory implements PrincipalFactory {

    private static final long serialVersionUID = 1L;

    public TaraPrincipalFactory() {
    }

    public Principal createPrincipal(String id) {
        throw new IllegalArgumentException("Attributes are mandatory when creating principal");
    }

    public Principal createPrincipal(String id, Map<String, Object> attributes) {
        if (MapUtils.isEmpty(attributes)) {
            throw new IllegalArgumentException("No any attributes found when creating principal");
        }
        return new TaraPrincipal(id, attributes);
    }

    public boolean equals(Object obj) {
        return obj == null ? false : (obj == this ? true : obj.getClass() == this.getClass());
    }

    public int hashCode() {
        return (new HashCodeBuilder(13, 33)).toHashCode();
    }

}
