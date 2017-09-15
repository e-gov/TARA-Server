//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.authentication.principal;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.SimplePrincipal;

public class DefaultPrincipalFactory implements PrincipalFactory {
	private static final long serialVersionUID = -3999695695604948495L;

	public DefaultPrincipalFactory() {
	}

	public Principal createPrincipal(String id) {
		throw new RuntimeException("123");
		//return new SimplePrincipal(id, new HashMap());
	}

	public Principal createPrincipal(String id, Map<String, Object> attributes) {
		if (attributes == null ||attributes.size() == 0) {
			throw new RuntimeException("attributes NULL");
		}
		return new SimplePrincipal(id, attributes);
	}

	public boolean equals(Object obj) {
		return obj == null?false:(obj == this?true:obj.getClass() == this.getClass());
	}

	public int hashCode() {
		return (new HashCodeBuilder(13, 33)).toHashCode();
	}
}
