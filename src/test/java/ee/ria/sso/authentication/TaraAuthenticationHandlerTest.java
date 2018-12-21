package ee.ria.sso.authentication;

import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.authentication.principal.TaraPrincipal;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.principal.Principal;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public class TaraAuthenticationHandlerTest {

    private static final String MOCK_PRINCIPAL_CODE = "principalCode";
    private static final String MOCK_FIRST_NAME = "First-Name";
    private static final String MOCK_LAST_NAME = "Surname";
    private static final String MOCK_DATE_OF_BIRTH = "2018-08-22";

    private TaraAuthenticationHandler authenticationHandler;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

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
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(null);
        Assert.assertNull(authenticationHandlerExecutionResult);
    }

    @Test
    public void doAuthenticationShouldReturnNullWhenCredentialIsNotTaraCredential() throws GeneralSecurityException, PreventedException {
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(createNonTaraCredential());
        Assert.assertNull(authenticationHandlerExecutionResult);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidIdCardCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.IDCard, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.IDCard);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidMobileIdCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.MobileID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.MobileID);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithoutLoA() throws GeneralSecurityException, PreventedException {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Missing mandatory attribute! LoA is required in case of eIDAS");

        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setDateOfBirth(MOCK_DATE_OF_BIRTH);

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS);
        expectedAttributes.put(TaraPrincipal.Attribute.DATE_OF_BIRTH.name(), MOCK_DATE_OF_BIRTH);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithLoA() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        credential.setDateOfBirth(MOCK_DATE_OF_BIRTH);
        credential.setLevelOfAssurance(LevelOfAssurance.SUBSTANTIAL);

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS);
        expectedAttributes.put(TaraPrincipal.Attribute.DATE_OF_BIRTH.name(), MOCK_DATE_OF_BIRTH);
        expectedAttributes.put(TaraPrincipal.Attribute.LEVEL_OF_ASSURANCE.name(), LevelOfAssurance.SUBSTANTIAL.getAcrName());
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidBanklinkCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.BankLink);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidSmartIdCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.SmartID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.SmartID);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }


    private void verifyAuthenticationHandlerExecutionResult(AuthenticationHandlerExecutionResult AuthenticationHandlerExecutionResult, Map<String, Object> expectedAttributes) {
        Assert.assertNotNull("AuthenticationHandlerExecutionResult must not be null!", AuthenticationHandlerExecutionResult);

        Principal principal = AuthenticationHandlerExecutionResult.getPrincipal();
        Assert.assertNotNull("Principal must not be null!", principal);
        Assert.assertEquals(MOCK_PRINCIPAL_CODE, principal.getId());

        Map<String, Object> principalAttributes = principal.getAttributes();
        Assert.assertEquals(expectedAttributes.entrySet(), principalAttributes.entrySet());
    }

    private Map<String, Object> buildCommonExpectedAttributesMap(AuthenticationType type) {
        Map<String, Object> expectedAttributes = new HashMap<>();
        expectedAttributes.put(TaraPrincipal.Attribute.AUTHENTICATION_TYPE.name(), type.getAmrName());
        expectedAttributes.put(TaraPrincipal.Attribute.PRINCIPAL_CODE.name(), MOCK_PRINCIPAL_CODE);
        expectedAttributes.put(TaraPrincipal.Attribute.GIVEN_NAME.name(), MOCK_FIRST_NAME);
        expectedAttributes.put(TaraPrincipal.Attribute.FAMILY_NAME.name(), MOCK_LAST_NAME);
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
