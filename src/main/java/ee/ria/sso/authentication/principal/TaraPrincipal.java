package ee.ria.sso.authentication.principal;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import org.apereo.cas.authentication.principal.Principal;

import java.util.Map;
import java.util.TreeMap;

@AllArgsConstructor
@EqualsAndHashCode
public class TaraPrincipal implements Principal {

    public enum Attribute {
        PRINCIPAL_CODE,
        GIVEN_NAME,
        FAMILY_NAME,
        AUTHENTICATION_TYPE,
        DATE_OF_BIRTH,
        EMAIL,
        EMAIL_VERIFIED,
        LEVEL_OF_ASSURANCE;
    }

    private String id;
    private Map<String, Object> attributes;

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String toString() {
        return this.id;
    }

    @Override
    public Map<String, Object> getAttributes() {
        TreeMap map = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        map.putAll(this.attributes);
        return map;
    }
}
