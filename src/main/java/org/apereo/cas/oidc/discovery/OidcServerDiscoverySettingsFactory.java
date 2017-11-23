package org.apereo.cas.oidc.discovery;

import java.util.Arrays;
import java.util.Collections;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.springframework.beans.factory.FactoryBean;

/**
 * Created by serkp on 22.09.2017.
 */

public class OidcServerDiscoverySettingsFactory implements FactoryBean<OidcServerDiscoverySettings> {

	private final CasConfigurationProperties casProperties;

	public OidcServerDiscoverySettingsFactory(final CasConfigurationProperties casProperties) {
		this.casProperties = casProperties;
	}

	@Override
	public OidcServerDiscoverySettings getObject() throws Exception {
		final OidcProperties oidc = casProperties.getAuthn().getOidc();
		final OidcServerDiscoverySettings discoveryProperties =
				new OidcServerDiscoverySettings(casProperties, oidc.getIssuer());
		discoveryProperties.setClaimsSupported(oidc.getClaims());
		discoveryProperties.setScopesSupported(oidc.getScopes());
		discoveryProperties.setResponseTypesSupported(
				Collections.singletonList(OAuth20ResponseTypes.CODE.getType()));
		discoveryProperties.setSubjectTypesSupported(oidc.getSubjectTypes());
		discoveryProperties.setClaimTypesSupported(Collections.singletonList("normal"));
		discoveryProperties.setGrantTypesSupported(
				Collections.singletonList(OAuth20GrantTypes.AUTHORIZATION_CODE.getType()));
		discoveryProperties.setIdTokenSigningAlgValuesSupported(Arrays.asList("none", "RS256"));
		return discoveryProperties;
	}

	@Override
	public Class<?> getObjectType() {
		return OidcServerDiscoverySettings.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

}
