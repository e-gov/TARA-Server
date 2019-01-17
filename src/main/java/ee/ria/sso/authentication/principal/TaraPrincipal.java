package ee.ria.sso.authentication.principal;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import lombok.EqualsAndHashCode;
import org.apereo.cas.authentication.principal.Principal;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@JsonIgnoreProperties(
    ignoreUnknown = true
)
@EqualsAndHashCode
public class TaraPrincipal implements Principal {

    public enum Attribute {
        PRINCIPAL_CODE,
        GIVEN_NAME,
        FAMILY_NAME,
        AUTHENTICATION_TYPE,
        DATE_OF_BIRTH,
        LEVEL_OF_ASSURANCE;
    }

    private static final long serialVersionUID = 1L;
    private Map<String, Object> attributes;

    @JsonProperty
    private String id;

    @JsonCreator
    protected TaraPrincipal(@JsonProperty("id") String id, @JsonProperty("attributes") Map<String, Object> attributes) {
        Assert.notNull(id, "ID is null");
        this.id = id;
        if (attributes == null) {
            this.attributes = Collections.emptyMap();
        } else {
            this.attributes = attributes;
        }
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String toString() {
        return this.id;
    }

    public Map<String, Object> getAttributes() {
        TreeMap map = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        map.putAll(this.attributes);
        return map;
    }

}
