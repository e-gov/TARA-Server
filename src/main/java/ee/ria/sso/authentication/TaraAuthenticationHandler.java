package ee.ria.sso.authentication;

import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.utils.EstonianIdCodeUtil;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.util.Assert;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.*;

public class TaraAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    public TaraAuthenticationHandler(ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super("", servicesManager, principalFactory, order);
    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof TaraCredential;
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {

        if (credential instanceof TaraCredential) {
            TaraCredential taraCredential = (TaraCredential) credential;

            Assert.noNullElements(new Object[] {
                    taraCredential.getPrincipalCode(),
                    taraCredential.getFirstName(),
                    taraCredential.getLastName(),
                    taraCredential.getType()
            }, "Cannot authenticate without missing mandatory credential parameters! Provided credential: " + credential);

            final Map<String, Object> map = new LinkedHashMap<>();
            map.put(PRINCIPAL_CODE.name(), taraCredential.getPrincipalCode());
            map.put(GIVEN_NAME.name(), taraCredential.getFirstName());
            map.put(FAMILY_NAME.name(), taraCredential.getLastName());
            map.put(AUTHENTICATION_TYPE.name(), taraCredential.getType().getAmrName());

            if (taraCredential.getType() == AuthenticationType.eIDAS) {
                Assert.notNull(taraCredential.getDateOfBirth(), "Missing mandatory attribute! Date of birth is required in case of eIDAS");
                Assert.notNull(taraCredential.getLevelOfAssurance(), "Missing mandatory attribute! LoA is required in case of eIDAS");
                map.put(DATE_OF_BIRTH.name(), taraCredential.getDateOfBirth());
                map.put(LEVEL_OF_ASSURANCE.name(), taraCredential.getLevelOfAssurance().getAcrName());
            } else if (EstonianIdCodeUtil.isEEPrefixedEstonianIdCode(taraCredential.getPrincipalCode())) {
                map.put(DATE_OF_BIRTH.name(), EstonianIdCodeUtil.extractDateOfBirthFromEEPrefixedEstonianIdCode(taraCredential.getPrincipalCode()));
            }

            return this.createHandlerResult(credential, this.principalFactory
                .createPrincipal(taraCredential.getId(), map), new ArrayList<>());
        }
        return null;
    }
}
