package ee.ria.sso.authentication.principal;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
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
public class TaraPrincipal implements Principal {

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

    @Override
    public int hashCode() {
        HashCodeBuilder builder = new HashCodeBuilder(83, 31);
        builder.append(this.id.toLowerCase());
        return builder.toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        } else if (obj == this) {
            return true;
        } else if (obj.getClass() != this.getClass()) {
            return false;
        } else {
            return StringUtils.equalsIgnoreCase(this.id, ((TaraPrincipal) obj).getId());
        }
    }

    public Map<String, Object> getAttributes() {
        TreeMap map = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        map.putAll(this.attributes);
        return map;
    }

}
