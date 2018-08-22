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
    private static final String MOCK_MOBILE_NUMBER = "87654321";
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
    public void doAuthenticationShouldReturnValidResultWhenPrincipalCodeAndNamesArePresent() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.IDCard, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.IDCard);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultWhenPrincipalCodeAndNamesAndMobileNumberArePresent() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.MobileID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setMobileNumber(MOCK_MOBILE_NUMBER);

        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.MobileID);
        expectedAttributes.put("mobileNumber", MOCK_MOBILE_NUMBER);
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultWhenPrincipalCodeAndNamesAndBirthDateAndLoaArePresent() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setDateOfBirth(MOCK_DATE_OF_BIRTH);
        credential.setLevelOfAssurance(LevelOfAssurance.SUBSTANTIAL);

        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS);
        expectedAttributes.put("dateOfBirth", MOCK_DATE_OF_BIRTH);
        expectedAttributes.put("levelOfAssurance", LevelOfAssurance.SUBSTANTIAL.getAcrName());
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultWhenPrincipalCodeAndNamesAndBankArePresent() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setBanklinkType(BankEnum.SEB);

        HandlerResult handlerResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.BankLink);
        expectedAttributes.put("banklinkType", BankEnum.SEB.getName().toUpperCase());
        verifyHandlerResult(handlerResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultWhenPrincipalCodeAndNamesArePresent2() throws GeneralSecurityException, PreventedException {
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
        expectedAttributes.put("authenticationType", type.getAmrName());
        expectedAttributes.put("principalCode", MOCK_PRINCIPAL_CODE);
        expectedAttributes.put("firstName", MOCK_FIRST_NAME);
        expectedAttributes.put("lastName", MOCK_LAST_NAME);
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
