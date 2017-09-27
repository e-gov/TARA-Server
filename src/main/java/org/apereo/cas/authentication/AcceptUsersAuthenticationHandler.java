package org.apereo.cas.authentication;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

/**
 *
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
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

		attributeMap.put("firstName", usernamePasswordCredential.getGivenName());
		attributeMap.put("lastName", usernamePasswordCredential.getFamilyName());
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