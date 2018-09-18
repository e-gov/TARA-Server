package ee.ria.sso.authentication;

import ee.ria.sso.authentication.credential.TaraCredential;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.principal.Principal;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public class TaraAuthenticationHandlerTest {

    private static final String MOCK_PRINCIPAL_CODE = "principalCode";
    private static final String MOCK_FIRST_NAME = "First-Name";
    private static final String MOCK_LAST_NAME = "Surname";
    private static final String MOCK_DATE_OF_BIRTH = "2018-08-22";

    private TaraAuthenticationHandler authenticationHandler;

    @Before
    public void setUp() {
        authenticationHandler = new TaraAuthenticationHandler(null, null, null);
    }


    @Test
    public void supportsShouldReturnFalseWhenCredentialIsMissing() {
        boolean result = authenticationHandler.supports(null);
        Assert.assertFalse("TaraAuthenticationHandler is expected to not support null!", result);
    }

    @Test
    public void supportsShouldReturnFalseWhenCredentialIsNotTaraCredential() {
        boolean result = authenticationHandler.supports(createNonTaraCredential());
        Assert.assertFalse("TaraAuthenticationHandler is expected to not support non-TaraCredential!", result);
    }

    @Test
    public void supportsShouldReturnTrueWhenCredentialIsTaraCredential() {
        boolean result = authenticationHandler.supports(new TaraCredential());
        Assert.assertTrue("TaraAuthenticationHandler is expected to support TaraCredential!", result);
    }

    @Test
    public void supportsShouldReturnTrueWhenCredentialExtendsTaraCredential() {
        boolean result = authenticationHandler.supports(new TaraCredential() {});
        Assert.assertTrue("TaraAuthenticationHandler is expected to support TaraCredential!", result);
    }


    @Test
    public void doAuthenticationShouldReturnNullWhenCredentialIsMissing() throws GeneralSecurityException, PreventedException {
        HandlerResult handlerResult = authenticationHandler.doAuthentication(null);
        Assert.assertNull(handlerResult);
    }

    @Test
    public void doAuthenticationShouldReturnNullWhenCredentialIsNotTaraCredential() throws GeneralSecurityException, PreventedException {
        HandlerResult handlerResult = authenticationHandler.doAuthentication(createNonTaraCredential());
        Assert.assertNull(handlerResult);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidIdCardCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.IDCard, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.IDCard);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidMobileIdCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.MobileID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.MobileID);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithoutLoA() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setDateOfBirth(MOCK_DATE_OF_BIRTH);

        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS);
        expectedAttributes.put("date_of_birth", MOCK_DATE_OF_BIRTH);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithLoA() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setDateOfBirth(MOCK_DATE_OF_BIRTH);
        credential.setLevelOfAssurance(LevelOfAssurance.SUBSTANTIAL);

        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS);
        expectedAttributes.put("date_of_birth", MOCK_DATE_OF_BIRTH);
        expectedAttributes.put("level_of_assurance", LevelOfAssurance.SUBSTANTIAL.getAcrName());
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidBanklinkCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.BankLink);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidSmartIdCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.SmartID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.SmartID);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }


    private void verifyHandlerResult(HandlerResult handlerResult, Map<String, Object> expectedAttributes) {
        Assert.assertNotNull("HandlerResult must not be null!", handlerResult);

        Principal principal = handlerResult.getPrincipal();
        Assert.assertNotNull("Principal must not be null!", principal);
        Assert.assertEquals(MOCK_PRINCIPAL_CODE, principal.getId());

        Map<String, Object> principalAttributes = principal.getAttributes();
        Assert.assertEquals(expectedAttributes.entrySet(), principalAttributes.entrySet());
    }

    private Map<String, Object> buildCommonExpectedAttributesMap(AuthenticationType type) {
        Map<String, Object> expectedAttributes = new HashMap<>();
        expectedAttributes.put("authentication_type", type.getAmrName());
        expectedAttributes.put("principal_code", MOCK_PRINCIPAL_CODE);
        expectedAttributes.put("given_name", MOCK_FIRST_NAME);
        expectedAttributes.put("family_name", MOCK_LAST_NAME);
        return expectedAttributes;
    }

    private Credential createNonTaraCredential() {
        return new Credential() {
            @Override
            public String getId() {
                return "id";
            }
        };
    }
}
