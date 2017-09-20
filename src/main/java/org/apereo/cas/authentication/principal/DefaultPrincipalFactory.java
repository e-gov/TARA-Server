//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.authentication.principal;

import java.util.Map;

import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

public class DefaultPrincipalFactory implements PrincipalFactory {
	private static final long serialVersionUID = -3999695695604948495L;

	public DefaultPrincipalFactory() {
	}

	public Principal createPrincipal(String id) {
		throw new RuntimeException("Not authorized to create Principal without attributes");
	}

	public Principal createPrincipal(String id, Map<String, Object> attributes) {
		if (attributes == null || attributes.size() == 0) {
			throw new RuntimeException("attributes NULL");
		}
		return new SimplePrincipal(id, attributes);
	}

	public boolean equals(Object obj) {
		return obj == null ? false : (obj == this ? true : obj.getClass() == this.getClass());
	}

	public int hashCode() {
		return (new HashCodeBuilder(13, 33)).toHashCode();
	}
}
