package org.apereo.cas.authentication;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;

import ee.ria.sso.AttributeConstant;
import ee.ria.sso.AttributesService;

/**
 * Created by serkp on 8.09.2017.
 */
public class AcceptUsersAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

	public AcceptUsersAuthenticationHandler(final String name, final ServicesManager servicesManager, final PrincipalFactory principalFactory,
			final Integer order) {
		super(name, servicesManager, principalFactory, order);
	}

	@Override
	public HandlerResult authenticate(Credential credential) throws GeneralSecurityException, PreventedException {
		return doAuthentication(credential);
	}

	@Override
	protected HandlerResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {
		UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;

		final Map<String, Object> attributeMap = new LinkedHashMap<>();

		attributeMap.put("firstName", usernamePasswordCredential.getFirstName());
		attributeMap.put("lastName", usernamePasswordCredential.getLastName());
		attributeMap.put("mobileNumber", usernamePasswordCredential.getMobileNumber());
		attributeMap.put("personalCode", usernamePasswordCredential.getPersonalCode());

		final List<MessageDescriptor> list = new ArrayList<>();
		return createHandlerResult(credential, this.principalFactory.createPrincipal(usernamePasswordCredential.getPersonalCode(), attributeMap), list);
	}

	@Override
	public boolean supports(Credential credential) {
		return true;
	}
}