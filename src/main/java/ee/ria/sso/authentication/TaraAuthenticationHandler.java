package ee.ria.sso.authentication;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

import ee.ria.sso.authentication.credential.TaraCredential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    public TaraAuthenticationHandler(ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super("", servicesManager, principalFactory, order);
    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof TaraCredential;
    }

    /*
     * RESTRICTED METHODS
     */

    // TODO: this class extracts attributes from TaraCredential and inserts them into a map

    @Override
    protected HandlerResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {
        final Map<String, Object> map = new LinkedHashMap<>();
        if (credential instanceof TaraCredential) {
            TaraCredential taraCredential = (TaraCredential) credential;
            this.putIfNotEmpty(map, "principalCode", taraCredential.getPrincipalCode());
            this.putIfNotEmpty(map, "firstName", taraCredential.getFirstName());
            this.putIfNotEmpty(map, "lastName", taraCredential.getLastName());
            this.putIfNotEmpty(map, "authenticationType", taraCredential.getType().getAmrName());
            if (AuthenticationType.MobileID.equals(taraCredential.getType())) {
                this.putIfNotEmpty(map, "mobileNumber", taraCredential.getMobileNumber());
            }
            if (AuthenticationType.eIDAS.equals(taraCredential.getType())) {
                this.putIfNotEmpty(map, "dateOfBirth", taraCredential.getDateOfBirth());
                if (taraCredential.getLevelOfAssurance() != null)
                    map.put("levelOfAssurance", taraCredential.getLevelOfAssurance().getAcrName());
            }
            return this.createHandlerResult(credential, this.principalFactory
                .createPrincipal(taraCredential.getId(), map), new ArrayList<>());
        }
        return null;
    }

    private void putIfNotEmpty(Map<String, Object> map, String attribute, String value) {
        if (StringUtils.isNotBlank(value)) {
            map.put(attribute, value);
        }
    }

}
