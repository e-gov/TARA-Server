package ee.ria.sso.authentication;

import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.authentication.principal.TaraPrincipal;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.service.eidas.EidasCredential;
import ee.ria.sso.service.idcard.IdCardCredential;
import ee.ria.sso.service.mobileid.MobileIDCredential;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.principal.Principal;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.GeneralSecurityException;
import java.util.*;

@RunWith(MockitoJUnitRunner.class)
public class TaraAuthenticationHandlerTest {

    private static final String MOCK_PRINCIPAL_CODE = "EE47101010033";
    private static final String MOCK_FIRST_NAME = "MARI-LIIS";
    private static final String MOCK_LAST_NAME = "MÄNNIK";
    private static final String MOCK_DATE_OF_BIRTH = "1971-01-01";
    private static final String MOCK_EMAIL = "mariliis-mannik@eesti.ee";
    private static final String MOCK_PHONE_NUMBER = "+3725123123";
    private static final String MOCK_ACR = "high";

    private TaraAuthenticationHandler authenticationHandler;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    TaraProperties taraProperties;

    @Before
    public void setUp() {
        authenticationHandler = new TaraAuthenticationHandler(null, null, null, taraProperties);
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
        boolean result = authenticationHandler.supports(new TaraCredential(AuthenticationType.IDCard, "", "", ""));
        Assert.assertTrue("TaraAuthenticationHandler is expected to support TaraCredential!", result);
    }

    @Test
    public void supportsShouldReturnTrueWhenCredentialExtendsTaraCredential() {
        boolean result = authenticationHandler.supports(new TaraCredential(AuthenticationType.IDCard, "", "","") {});
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
        setAuthenticationMethodLoa(Collections.singletonMap(AuthenticationType.IDCard, LevelOfAssurance.HIGH));
        IdCardCredential credential = new IdCardCredential(MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME, MOCK_EMAIL);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.IDCard, MOCK_ACR);
        expectedAttributes.put(TaraPrincipal.Attribute.EMAIL.name(), MOCK_EMAIL);
        expectedAttributes.put(TaraPrincipal.Attribute.EMAIL_VERIFIED.name(), false);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidMobileIdCredential() throws GeneralSecurityException, PreventedException {
        MobileIDCredential credential = new MobileIDCredential(MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        setAuthenticationMethodLoa(Collections.singletonMap(AuthenticationType.MobileID, LevelOfAssurance.HIGH));

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.MobileID, MOCK_ACR);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidMobileIdCredentialWithPhoneNumber() throws GeneralSecurityException, PreventedException {
        MobileIDCredential credential = new MobileIDCredential(MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME, MOCK_PHONE_NUMBER);
        setAuthenticationMethodLoa(Collections.singletonMap(AuthenticationType.MobileID, LevelOfAssurance.HIGH));

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.MobileID, MOCK_ACR);
        expectedAttributes.put(TaraPrincipal.Attribute.PHONE_NUMBER.name(), MOCK_PHONE_NUMBER);
        expectedAttributes.put(TaraPrincipal.Attribute.PHONE_NUMBER_VERIFIED.name(), false);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithoutLoA() throws GeneralSecurityException, PreventedException {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Missing mandatory attribute! LoA is required in case of eIDAS");

        EidasCredential credential = new EidasCredential(MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME, MOCK_DATE_OF_BIRTH, null);

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS, MOCK_ACR);
        expectedAttributes.put(TaraPrincipal.Attribute.DATE_OF_BIRTH.name(), MOCK_DATE_OF_BIRTH);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidEidasCredentialWithLoA() throws GeneralSecurityException, PreventedException {
        EidasCredential credential = new EidasCredential(MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME, MOCK_DATE_OF_BIRTH, LevelOfAssurance.SUBSTANTIAL);

        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.eIDAS, MOCK_ACR);
        expectedAttributes.put(TaraPrincipal.Attribute.DATE_OF_BIRTH.name(), MOCK_DATE_OF_BIRTH);
        expectedAttributes.put(TaraPrincipal.Attribute.ACR.name(), LevelOfAssurance.SUBSTANTIAL.getAcrName());
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidBanklinkCredential() throws GeneralSecurityException, PreventedException {
        setAuthenticationMethodLoa(Collections.singletonMap(AuthenticationType.BankLink, LevelOfAssurance.LOW));
        TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);

        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.BankLink, LevelOfAssurance.LOW.getAcrName());
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }

    @Test
    public void doAuthenticationShouldReturnValidResultForValidSmartIdCredential() throws GeneralSecurityException, PreventedException {
        TaraCredential credential = new TaraCredential(AuthenticationType.SmartID, MOCK_PRINCIPAL_CODE, MOCK_FIRST_NAME, MOCK_LAST_NAME);

        // with loa
        setAuthenticationMethodLoa(Collections.singletonMap(AuthenticationType.SmartID, LevelOfAssurance.SUBSTANTIAL));
        AuthenticationHandlerExecutionResult authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);
        Map<String, Object> expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.SmartID, LevelOfAssurance.SUBSTANTIAL.getAcrName());
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);

        // without loa
        setAuthenticationMethodLoa(null);
        authenticationHandlerExecutionResult = authenticationHandler.doAuthentication(credential);
        expectedAttributes = buildCommonExpectedAttributesMap(AuthenticationType.SmartID, null);
        verifyAuthenticationHandlerExecutionResult(authenticationHandlerExecutionResult, expectedAttributes);
    }


    private void verifyAuthenticationHandlerExecutionResult(AuthenticationHandlerExecutionResult AuthenticationHandlerExecutionResult, Map<String, Object> expectedAttributes) {
        Assert.assertNotNull("AuthenticationHandlerExecutionResult must not be null!", AuthenticationHandlerExecutionResult);

        Principal principal = AuthenticationHandlerExecutionResult.getPrincipal();
        Assert.assertNotNull("Principal must not be null!", principal);
        Assert.assertEquals(MOCK_PRINCIPAL_CODE, principal.getId());
        Assert.assertEquals(expectedAttributes, principal.getAttributes());
    }

    private Map<String, Object> buildCommonExpectedAttributesMap(AuthenticationType type, String expectedAcr) {
        Map<String, Object> expectedAttributes = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        expectedAttributes.put(TaraPrincipal.Attribute.AMR.name(), Arrays.asList(Arrays.asList(type.getAmrName())));
        expectedAttributes.put(TaraPrincipal.Attribute.SUB.name(), MOCK_PRINCIPAL_CODE);
        expectedAttributes.put(TaraPrincipal.Attribute.GIVEN_NAME.name(), MOCK_FIRST_NAME);
        expectedAttributes.put(TaraPrincipal.Attribute.FAMILY_NAME.name(), MOCK_LAST_NAME);
        expectedAttributes.put(TaraPrincipal.Attribute.DATE_OF_BIRTH.name(), MOCK_DATE_OF_BIRTH);
        if (expectedAcr != null)
            expectedAttributes.put(TaraPrincipal.Attribute.ACR.name(), expectedAcr);
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

    private void setAuthenticationMethodLoa(Map<AuthenticationType, LevelOfAssurance> authMethodsToLoaMap) {
        Mockito.when(taraProperties.getAuthenticationMethodsLoaMap()).thenReturn(authMethodsToLoaMap);
    }
}
