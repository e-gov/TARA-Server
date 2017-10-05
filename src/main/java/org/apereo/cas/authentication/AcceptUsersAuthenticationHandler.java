package org.apereo.cas.authentication;


import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apereo.cas.authentication.handler.support
        .AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;


/**
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

public class AcceptUsersAuthenticationHandler
        extends AbstractPreAndPostProcessingAuthenticationHandler {

    public AcceptUsersAuthenticationHandler(final String name,
                                            final ServicesManager servicesManager,
                                            final PrincipalFactory principalFactory,
                                            final Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    public HandlerResult authenticate(Credential credential)
            throws GeneralSecurityException, PreventedException {
        return doAuthentication(credential);
    }

    @Override
    protected HandlerResult doAuthentication(Credential credential)
            throws GeneralSecurityException, PreventedException {
        final Map<String, Object> attributeMap = new LinkedHashMap<>();
        if (credential instanceof UsernamePasswordCredential) {
            UsernamePasswordCredential usernamePasswordCredential =
                    (UsernamePasswordCredential) credential;
            putIfNotEmpty(attributeMap, "firstName", usernamePasswordCredential.getGivenName());
            putIfNotEmpty(attributeMap, "lastName", usernamePasswordCredential.getFamilyName());

            if (usernamePasswordCredential
                    .getAuthenticationType().equals("MID")) {
                putIfNotEmpty(attributeMap, "mobileNumber",
                              usernamePasswordCredential.getMobileNumber()
                );
            }
            return createHandlerResult(credential, this.principalFactory
                                               .createPrincipal(usernamePasswordCredential
                                                                        .getPrincipalCode(),
                                                                attributeMap),
                                       new ArrayList<>());
        }
        return null;
    }

    private void putIfNotEmpty(Map<String, Object> attributeMap, String attribute, String value) {
        if (value != null && value.trim().length() > 0) {
            attributeMap.put(attribute, value);
        }
    }

    @Override
    public boolean supports(Credential credential) {
        return true;
    }
}