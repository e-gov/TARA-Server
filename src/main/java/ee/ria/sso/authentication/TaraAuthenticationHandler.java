package ee.ria.sso.authentication;

import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.service.eidas.EidasCredential;
import ee.ria.sso.service.idcard.IdCardCredential;
import ee.ria.sso.service.mobileid.MobileIDCredential;
import ee.ria.sso.utils.EstonianIdCodeUtil;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.util.Assert;

import java.security.GeneralSecurityException;
import java.util.*;

import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.*;

public class TaraAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    private TaraProperties taraProperties;

    public TaraAuthenticationHandler(ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order, TaraProperties taraProperties) {
        super("", servicesManager, principalFactory, order);
        this.taraProperties = taraProperties;
    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof TaraCredential;
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {

        if (credential instanceof TaraCredential) {
            TaraCredential taraCredential = (TaraCredential) credential;
            final Map<String, Object> principalAttributes = getMandatoryPrincipalParameters(taraCredential);

            if (isLoaDefinedByConf(taraCredential.getType())) {
                principalAttributes.put(ACR.name(), taraProperties.getAuthenticationMethodsLoaMap().get(taraCredential.getType()).getAcrName());
            }

            if (credential instanceof IdCardCredential && ((IdCardCredential)taraCredential).getEmail() != null) {
                principalAttributes.put(EMAIL.name(), ((IdCardCredential)taraCredential).getEmail());
                principalAttributes.put(EMAIL_VERIFIED.name(), ((IdCardCredential)taraCredential).getEmailVerified());
            } else if (credential instanceof EidasCredential) {
                principalAttributes.put(DATE_OF_BIRTH.name(), ((EidasCredential)taraCredential).getDateOfBirth());
                principalAttributes.put(ACR.name(),((EidasCredential)taraCredential).getLevelOfAssurance().getAcrName());
            } else if (credential instanceof MobileIDCredential && ((MobileIDCredential)taraCredential).getPhoneNumber() != null) {
                principalAttributes.put(PHONE_NUMBER.name(), ((MobileIDCredential)taraCredential).getPhoneNumber());
                principalAttributes.put(PHONE_NUMBER_VERIFIED.name(), ((MobileIDCredential)taraCredential).getPhoneNumberVerified());
            }

            return this.createHandlerResult(credential, this.principalFactory
                .createPrincipal(taraCredential.getId(), principalAttributes), new ArrayList<>());
        }
        return null;
    }

    private boolean isLoaDefinedByConf(AuthenticationType type) {
        return taraProperties != null && taraProperties.getAuthenticationMethodsLoaMap() != null
                && taraProperties.getAuthenticationMethodsLoaMap().containsKey(type);
    }

    private Map<String, Object> getMandatoryPrincipalParameters(TaraCredential taraCredential) {
        Assert.noNullElements(new Object[] {
                taraCredential.getPrincipalCode(),
                taraCredential.getFirstName(),
                taraCredential.getLastName(),
                taraCredential.getType()
        }, "Cannot authenticate without missing mandatory credential parameters! Provided credential: " + taraCredential);

        final Map<String, Object> map = new LinkedHashMap<>();
        map.put(SUB.name(), taraCredential.getPrincipalCode());
        map.put(GIVEN_NAME.name(), taraCredential.getFirstName());
        map.put(FAMILY_NAME.name(), taraCredential.getLastName());
        map.put(AMR.name(), Arrays.asList(Arrays.asList(taraCredential.getType().getAmrName())));

        if (EstonianIdCodeUtil.isEEPrefixedEstonianIdCode(taraCredential.getPrincipalCode())) {
            map.put(DATE_OF_BIRTH.name(), EstonianIdCodeUtil.extractDateOfBirthFromEEPrefixedEstonianIdCode(taraCredential.getPrincipalCode()));
        }
        return map;
    }
}
