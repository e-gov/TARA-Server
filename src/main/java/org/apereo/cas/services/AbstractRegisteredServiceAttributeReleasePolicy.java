//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.services;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.authentication.principal.DefaultPrincipalAttributesRepository;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalAttributesRepository;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceAttributeFilter;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicy;
import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

public abstract class AbstractRegisteredServiceAttributeReleasePolicy implements RegisteredServiceAttributeReleasePolicy {
	private static final long serialVersionUID = 5325460875620586503L;
	private static final Logger LOGGER = LoggerFactory.getLogger(AbstractRegisteredServiceAttributeReleasePolicy.class);
	private RegisteredServiceAttributeFilter registeredServiceAttributeFilter;
	private PrincipalAttributesRepository principalAttributesRepository = new DefaultPrincipalAttributesRepository();
	private boolean authorizedToReleaseCredentialPassword;
	private boolean authorizedToReleaseProxyGrantingTicket;
	private boolean excludeDefaultAttributes;
	private String principalIdAttribute;

	public AbstractRegisteredServiceAttributeReleasePolicy() {
	}

	public void setAttributeFilter(RegisteredServiceAttributeFilter filter) {
		this.registeredServiceAttributeFilter = filter;
	}

	public void setPrincipalAttributesRepository(PrincipalAttributesRepository repository) {
		this.principalAttributesRepository = repository;
	}

	public PrincipalAttributesRepository getPrincipalAttributesRepository() {
		return this.principalAttributesRepository;
	}

	public RegisteredServiceAttributeFilter getAttributeFilter() {
		return this.registeredServiceAttributeFilter;
	}

	public String getPrincipalIdAttribute() {
		return this.principalIdAttribute;
	}

	public void setPrincipalIdAttribute(String principalIdAttribute) {
		this.principalIdAttribute = principalIdAttribute;
	}

	public boolean isAuthorizedToReleaseCredentialPassword() {
		return this.authorizedToReleaseCredentialPassword;
	}

	public boolean isAuthorizedToReleaseProxyGrantingTicket() {
		return this.authorizedToReleaseProxyGrantingTicket;
	}

	public void setAuthorizedToReleaseCredentialPassword(boolean authorizedToReleaseCredentialPassword) {
		this.authorizedToReleaseCredentialPassword = authorizedToReleaseCredentialPassword;
	}

	public void setAuthorizedToReleaseProxyGrantingTicket(boolean authorizedToReleaseProxyGrantingTicket) {
		this.authorizedToReleaseProxyGrantingTicket = authorizedToReleaseProxyGrantingTicket;
	}

	public boolean isExcludeDefaultAttributes() {
		return this.excludeDefaultAttributes;
	}

	public void setExcludeDefaultAttributes(boolean excludeDefaultAttributes) {
		this.excludeDefaultAttributes = excludeDefaultAttributes;
	}

	public Map<String, Object> getAttributes(Principal principal, Service selectedService, RegisteredService registeredService) {
		LOGGER.debug("Locating principal attributes for [{}]", principal.getId());
		Map principalAttributes = this.getPrincipalAttributesRepository() == null?principal.getAttributes():this.getPrincipalAttributesRepository().getAttributes(principal);
		LOGGER.debug("Found principal attributes [{}] for [{}]", principalAttributes, principal.getId());
		LOGGER.debug("Calling attribute policy [{}] to process attributes for [{}]", this.getClass().getSimpleName(), principal.getId());
		Map policyAttributes = this.getAttributesInternal(principal, principalAttributes, registeredService);
		LOGGER.debug("Attribute policy [{}] allows release of [{}] for [{}]", new Object[]{this.getClass().getSimpleName(), policyAttributes, principal.getId()});
		LOGGER.debug("Attempting to merge policy attributes and default attributes");
		TreeMap attributesToRelease = new TreeMap(String.CASE_INSENSITIVE_ORDER);

		/*if(this.isExcludeDefaultAttributes()) {
			LOGGER.debug("Ignoring default attribute policy attributes");
		} else {
			LOGGER.debug("Checking default attribute policy attributes");
			Map defaultAttributes = this.getReleasedByDefaultAttributes(principal, principalAttributes);
			LOGGER.debug("Default attributes found to be released are [{}]", defaultAttributes);
			LOGGER.debug("Adding default attributes first to the released set of attributes");
			attributesToRelease.putAll(defaultAttributes);
		}*/

		LOGGER.debug("Adding policy attributes to the released set of attributes");
		attributesToRelease.putAll(policyAttributes);
		attributesToRelease.putAll(principalAttributes);
		this.insertPrincipalIdAsAttributeIfNeeded(principal, attributesToRelease, selectedService, registeredService);
		if(this.getAttributeFilter() != null) {
			LOGGER.debug("Invoking attribute filter [{}] on the final set of attributes", this.getAttributeFilter());
			return this.getAttributeFilter().filter(attributesToRelease);
		} else {
			return this.returnFinalAttributesCollection(attributesToRelease, registeredService);
		}
	}

	protected void insertPrincipalIdAsAttributeIfNeeded(Principal principal, Map<String, Object> attributesToRelease, Service service, RegisteredService registeredService) {
		if(StringUtils.isNotBlank(this.getPrincipalIdAttribute())) {
			LOGGER.debug("Attempting to resolve the principal id for service [{}]", registeredService.getServiceId());
			String id = registeredService.getUsernameAttributeProvider().resolveUsername(principal, service, registeredService);
			LOGGER.debug("Releasing resolved principal id [{}] as attribute [{}]", id, this.getPrincipalIdAttribute());
			attributesToRelease.put(this.getPrincipalIdAttribute(), principal.getId());
		}

	}

	protected Map<String, Object> returnFinalAttributesCollection(Map<String, Object> attributesToRelease, RegisteredService service) {
		LOGGER.debug("Final collection of attributes allowed are: [{}]", attributesToRelease);
		return attributesToRelease;
	}

	protected Map<String, Object> getReleasedByDefaultAttributes(Principal p, Map<String, Object> attributes) {
		ApplicationContext ctx = ApplicationContextProvider.getApplicationContext();
		if(ctx != null) {
			LOGGER.debug("Located application context. Retrieving default attributes for release, if any");
			CasConfigurationProperties props = (CasConfigurationProperties)ctx.getAutowireCapableBeanFactory().getBean(CasConfigurationProperties.class);
			Set defaultAttrs = props.getAuthn().getAttributeRepository().getDefaultAttributesToRelease();
			LOGGER.debug("Default attributes for release are: [{}]", defaultAttrs);
			TreeMap defaultAttributesToRelease = new TreeMap(String.CASE_INSENSITIVE_ORDER);
			defaultAttrs.stream().forEach((key) -> {
				if(attributes.containsKey(key)) {
					LOGGER.debug("Found and added default attribute for release: [{}]", key);
					defaultAttributesToRelease.put(key, attributes.get(key));
				}

			});
			return defaultAttributesToRelease;
		} else {
			return new TreeMap();
		}
	}

	protected abstract Map<String, Object> getAttributesInternal(Principal var1, Map<String, Object> var2, RegisteredService var3);

	public int hashCode() {
		return (new HashCodeBuilder(13, 133)).append(this.getAttributeFilter()).append(this.isAuthorizedToReleaseCredentialPassword()).append(this.isAuthorizedToReleaseProxyGrantingTicket()).append(this.getPrincipalAttributesRepository()).append(this.isExcludeDefaultAttributes()).append(this.getPrincipalIdAttribute()).toHashCode();
	}

	public boolean equals(Object o) {
		if(o == null) {
			return false;
		} else if(this == o) {
			return true;
		} else if(!(o instanceof AbstractRegisteredServiceAttributeReleasePolicy)) {
			return false;
		} else {
			AbstractRegisteredServiceAttributeReleasePolicy that = (AbstractRegisteredServiceAttributeReleasePolicy)o;
			EqualsBuilder builder = new EqualsBuilder();
			return builder.append(this.getAttributeFilter(), that.getAttributeFilter()).append(this.isAuthorizedToReleaseCredentialPassword(), that.isAuthorizedToReleaseCredentialPassword()).append(this.isAuthorizedToReleaseProxyGrantingTicket(), that.isAuthorizedToReleaseProxyGrantingTicket()).append(this.getPrincipalAttributesRepository(), that.getPrincipalAttributesRepository()).append(this.isExcludeDefaultAttributes(), that.isExcludeDefaultAttributes()).append(this.getPrincipalIdAttribute(), that.getPrincipalIdAttribute()).isEquals();
		}
	}

	public String toString() {
		return (new ToStringBuilder(this)).append("attributeFilter", this.getAttributeFilter()).append("principalAttributesRepository", this.getPrincipalAttributesRepository()).append("authorizedToReleaseCredentialPassword", this.isAuthorizedToReleaseCredentialPassword()).append("authorizedToReleaseProxyGrantingTicket", this.isAuthorizedToReleaseProxyGrantingTicket()).append("excludeDefaultAttributes", this.isExcludeDefaultAttributes()).append("principalIdAttribute", this.getPrincipalIdAttribute()).toString();
	}
}
