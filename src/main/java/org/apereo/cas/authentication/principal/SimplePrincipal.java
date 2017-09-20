//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.authentication.principal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apereo.cas.authentication.principal.Principal;
import org.springframework.util.Assert;

/**
 *
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

@JsonIgnoreProperties(
		ignoreUnknown = true
)
public class SimplePrincipal implements Principal {
	private static final long serialVersionUID = -1255260750151385796L;
	@JsonProperty
	private String id;
	private Map<String, Object> attributes;

	private SimplePrincipal() {
		this.id = null;
		this.attributes = new HashMap();
	}

	private SimplePrincipal(String id) {
		this(id, new HashMap());
	}

	@JsonCreator
	protected SimplePrincipal(@JsonProperty("id") String id, @JsonProperty("attributes") Map<String, Object> attributes) {
		Assert.notNull(id, "Principal id cannot be null");
		this.id = id;
		if(attributes == null) {
			this.attributes = new HashMap();
		} else {
			this.attributes = attributes;
		}

	}

	public Map<String, Object> getAttributes() {
		TreeMap attrs = new TreeMap(String.CASE_INSENSITIVE_ORDER);
		attrs.putAll(this.attributes);
		return attrs;
	}

	public String toString() {
		return this.id;
	}

	public int hashCode() {
		HashCodeBuilder builder = new HashCodeBuilder(83, 31);
		builder.append(this.id.toLowerCase());
		return builder.toHashCode();
	}

	public String getId() {
		return this.id;
	}

	public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		} else if(obj == this) {
			return true;
		} else if(obj.getClass() != this.getClass()) {
			return false;
		} else {
			SimplePrincipal rhs = (SimplePrincipal)obj;
			return StringUtils.equalsIgnoreCase(this.id, rhs.getId());
		}
	}
}
