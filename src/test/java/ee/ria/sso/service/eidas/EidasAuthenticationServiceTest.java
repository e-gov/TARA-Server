package ee.ria.sso.service.eidas;

import ee.ria.sso.CommonConstants;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.config.eidas.TestEidasConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;
import wiremock.com.fasterxml.jackson.core.JsonProcessingException;
import wiremock.com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@TestPropertySource(
        locations= "classpath:application-test.properties"
)
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestEidasConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class EidasAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String MOCK_PERSON_IDENTIFIER = "CZ/CZ/3121c47e-dea5-4ce6-b82b-cf4f8130fe89";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_DATE_OF_BIRTH = "2000-01-01";

    @Autowired
    private EidasConfigurationProvider configurationProvider;

    @Autowired
    private StatisticsHandler statistics;

    @Autowired
    private EidasConfigurationProvider eidasConfigurationProvider;

    @Mock
    private EidasAuthenticator authenticatorMock;

    private EidasAuthenticationService authenticationService;

    @Before
    public void setUp() {
        Mockito.reset(authenticatorMock);
        authenticationService = new EidasAuthenticationService(statistics, authenticatorMock, eidasConfigurationProvider);
    }

    @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByEidasWithoutLoaShouldSucceedAndWriteAuthenticatorResponse() throws Exception {
        String country = "FI";
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        credential.setCountry(country);

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        setAuthenticatorMockUpForAuthentication(country, null,"someAuthenticationResult");

        Event event = this.authenticationService.startLoginByEidas(requestContext);

        Assert.assertEquals("success", event.getId());
        this.verifyResponseResult(requestContext, "someAuthenticationResult");
        this.verifyLogContents(StatisticsOperation.START_AUTH, credential.getCountry().toUpperCase());
    }

    @Test
    public void startLoginByEidasWithLoaShouldSucceedAndWriteAuthenticatorResponse() throws Exception {
        String country = "FI";
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        credential.setCountry(country);

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        requestContext.getExternalContext().getSessionMap().put(Constants.TARA_OIDC_SESSION_LOA, LevelOfAssurance.HIGH);
        setAuthenticatorMockUpForAuthentication(country, LevelOfAssurance.HIGH,"someAuthenticationResult");

        Event event = this.authenticationService.startLoginByEidas(requestContext);

        Assert.assertEquals("success", event.getId());
        Assert.assertEquals(country.toUpperCase(),requestContext.getExternalContext().getSessionMap().get("country", String.class));
        this.verifyResponseResult(requestContext, "someAuthenticationResult");
        this.verifyLogContents(StatisticsOperation.START_AUTH, credential.getCountry().toUpperCase());
    }

    @Test
    public void startLoginByEidasShouldFailWhenInvalidCountryCodeFormat() throws Exception {
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        String country = "S";
        credential.setCountry(country);

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);

        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided invalid country code: <S>");

        try {
            Event event = this.authenticationService.startLoginByEidas(requestContext);
        } catch (Exception e) {
            Assert.assertTrue("Should not log to statistics when input is invalid", SimpleTestAppender.events.isEmpty());
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByEidasShouldFailWhenCountryCodeFormatValidButNotAllowed() {
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        credential.setCountry("RU");

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);

        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided not allowed country code: <RU>");

        try {
            this.authenticationService.startLoginByEidas(requestContext);
            Assert.fail("Expected to throw exception!");
        } catch (Exception e) {
            Assert.assertTrue("Should not log to statistics when input is invalid", SimpleTestAppender.events.isEmpty());
            throw e;
        }
    }

    @Test
    public void startLoginByEidasShouldFailWhenUnexpectedException() throws Exception {
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        String country = "FI";
        credential.setCountry(country);

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        requestContext.getExternalContext().getSessionMap().put("country", country);
        Mockito.doThrow(new IllegalStateException("Unexpected exception"))
                .when(authenticatorMock).authenticate(Mockito.any(), Mockito.any(), Mockito.any());

        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("Unexpected exception");

        try {
            Event event = this.authenticationService.startLoginByEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure(
                    "Unexpected exception", country, StatisticsOperation.START_AUTH);
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByEidasShouldFailWhenEidasAuthenticatorThrowsException() throws Exception {
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        String country = "FI";
        credential.setCountry(country);

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        requestContext.getExternalContext().getSessionMap().put("country", country);
        Mockito.doThrow(new IOException("Something went wrong in EidasAuthenticator.authenticate()"))
                .when(authenticatorMock).authenticate(Mockito.any(), Mockito.any(), Mockito.any());

        expectedEx.expect(ExternalServiceHasFailedException.class);
        expectedEx.expectMessage("eidas-client connection has failed: Something went wrong in EidasAuthenticator.authenticate()");

        try {
            Event event = this.authenticationService.startLoginByEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure(
                    "Something went wrong in EidasAuthenticator.authenticate()", country.toUpperCase(),
                    StatisticsOperation.START_AUTH);
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPresent() {
        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("SAML response's relay state (null) not found among previously stored relay states!");

        try {
            Event event = this.authenticationService.checkLoginForEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure("SAML response's relay state (null) not found among previously stored relay states!", "FI");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPreviouslyStored() {
        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("SAML response's relay state (someRelayState) not found among previously stored relay states!");

        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", "someRelayState");
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        try {
            Event event = this.authenticationService.checkLoginForEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure("SAML response's relay state (someRelayState) not found among previously stored relay states!", "FI");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasSucceeds() throws Exception {
        String relayState = UUID.randomUUID().toString();
        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("SAMLResponse", "someSamlResponse");
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", relayState);

        String serviceValueStoredAsRelayState = "someServiceValueStoreadAsRelayState";
        requestContext.getExternalContext().getSessionMap().put("service", serviceValueStoredAsRelayState);
        requestContext.getExternalContext().getSessionMap().put("relayState", relayState);
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        setAuthenticatorMockUpForAuthenticationResultRetrieval(requestContext,
                createMockAuthenticationResultString());

        Event event = this.authenticationService.checkLoginForEidas(requestContext);
        Assert.assertEquals("success", event.getId());

        validateUserCredential((EidasCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential"));
        Assert.assertEquals(serviceValueStoredAsRelayState, requestContext.getFlowScope().get("service"));
        Assert.assertNull("RelayState not deleted after successful verification", requestContext.getExternalContext().getSessionMap().get("relayState"));

        this.verifyLogContents(StatisticsOperation.SUCCESSFUL_AUTH, requestContext.getExternalContext().getSessionMap().get("country", String.class));
    }

    @Test
    public void checkLoginForEidasShouldfailWhenUserAuthenticationFails() throws Exception {
        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("eidasclient error");

        String relayState = UUID.randomUUID().toString();
        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("SAMLResponse", "someSamlResponse");
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", relayState);

        String serviceValueStoredAsRelayState = "someServiceValueStoreadAsRelayState";
        requestContext.getExternalContext().getSessionMap().put("service", serviceValueStoredAsRelayState);
        requestContext.getExternalContext().getSessionMap().put("relayState", relayState);
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        Mockito.doThrow(new EidasAuthenticationFailedException("eidasclient error"))
                .when(authenticatorMock).getAuthenticationResult(Mockito.any());

        try {
            this.authenticationService.checkLoginForEidas(requestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            verifyResourcesAreCleanedUp(requestContext);
            verifyLogContentsOnFailure("eidasclient error", requestContext.getExternalContext().getSessionMap().get("country", String.class));
            throw e;
        }
    }

    @Test
    public void checkLoginForEidasShouldfailWhenTechnicalException() throws Exception {
        expectedEx.expect(ExternalServiceHasFailedException.class);
        expectedEx.expectMessage("eidas-client connection has failed: Unexpected error");

        String relayState = UUID.randomUUID().toString();
        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("SAMLResponse", "someSamlResponse");
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", relayState);

        String serviceValueStoredAsRelayState = "someServiceValueStoreadAsRelayState";
        requestContext.getExternalContext().getSessionMap().put("service", serviceValueStoredAsRelayState);
        requestContext.getExternalContext().getSessionMap().put("relayState", relayState);
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        Mockito.doThrow(new IOException("Unexpected error"))
                .when(authenticatorMock).getAuthenticationResult(Mockito.any());

        try {
            this.authenticationService.checkLoginForEidas(requestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            verifyResourcesAreCleanedUp(requestContext);
            verifyLogContentsOnFailure("Unexpected error", requestContext.getExternalContext().getSessionMap().get("country", String.class));
            throw e;
        }
    }

    @Test
    public void checkLoginForEidasShouldfailWhenInvalidIdCodeFormatIsReturned() throws Exception {
        assertError("1234567890", ExternalServiceHasFailedException.class, "The person identifier has invalid format! <1234567890>");
        assertError("EE//1234567890", ExternalServiceHasFailedException.class, "The person identifier has invalid format! <EE//1234567890>");
        assertError("/EE/1234567890", ExternalServiceHasFailedException.class, "The person identifier has invalid format! </EE/1234567890>");
        assertError("FIN/EST/1234567890", ExternalServiceHasFailedException.class, "The person identifier has invalid format! <FIN/EST/1234567890>");
        assertError("//1234567890", ExternalServiceHasFailedException.class, "The person identifier has invalid format! <//1234567890>");
    }

    private void assertError(String personIdentifier, Class<ExternalServiceHasFailedException> expectedExceptionType, String expectedErrorMessage) throws IOException {

        SimpleTestAppender.events.clear();
        String relayState = UUID.randomUUID().toString();
        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("SAMLResponse", "someSamlResponse");
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", relayState);

        String serviceValueStoredAsRelayState = "someServiceValueStoreadAsRelayState";
        requestContext.getExternalContext().getSessionMap().put("service", serviceValueStoredAsRelayState);
        requestContext.getExternalContext().getSessionMap().put("relayState", relayState);
        requestContext.getExternalContext().getSessionMap().put("country", "FI");

        Mockito.when(authenticatorMock.getAuthenticationResult(Mockito.any())).thenReturn(
                ("{\n" +
                        "   \"levelOfAssurance\":\"http://eidas.europa.eu/LoA/substantial\",\n" +
                        "   \"attributes\":{\n" +
                        "      \"DateOfBirth\":\"1965-01-01\",\n" +
                        "      \"PersonIdentifier\":\"" + personIdentifier + "\",\n" +
                        "      \"FamilyName\":\"Ωνάσης\",\n" +
                        "      \"FirstName\":\"Αλέξανδρος\"\n" +
                        "   },\n" +
                        "   \"attributesTransliterated\":{\n" +
                        "      \"FamilyName\":\"Onassis\",\n" +
                        "      \"FirstName\":\"Alexander\"\n" +
                        "   }\n" +
                        "}").getBytes(StandardCharsets.UTF_8)
        );

        try {
            this.authenticationService.checkLoginForEidas(requestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            verifyResourcesAreCleanedUp(requestContext);
            verifyLogContentsOnFailure("The person identifier has invalid format! <" + personIdentifier + ">", requestContext.getExternalContext().getSessionMap().get("country", String.class));
            Assert.assertEquals(expectedExceptionType, e.getClass());
            Assert.assertEquals(expectedErrorMessage, e.getMessage());
        }
    }

    private void setAuthenticatorMockUpForAuthenticationResultRetrieval(final RequestContext context, final String result) throws Exception {
        Mockito.doThrow(new IllegalArgumentException("Invalid input arguments to EidasAuthenticator.getAuthenticationResult()"))
                .when(authenticatorMock).getAuthenticationResult(Mockito.any());

        Mockito.doReturn(result.getBytes(StandardCharsets.UTF_8)).when(authenticatorMock).getAuthenticationResult(
                Mockito.eq((HttpServletRequest) context.getExternalContext().getNativeRequest())
        );
    }

    private void validateUserCredential(EidasCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.eIDAS, credential.getType());
        Assert.assertEquals("EE" + MOCK_PERSON_IDENTIFIER, credential.getId());
        Assert.assertEquals(MOCK_FIRST_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_LAST_NAME, credential.getLastName());
        Assert.assertEquals(MOCK_DATE_OF_BIRTH, credential.getDateOfBirth());
    }

    private void verifyLogContents(StatisticsOperation statisticsOperation, String country) {
        AuthenticationType authenticationType = AuthenticationType.eIDAS;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType + "/" + country, statisticsOperation))
        );
    }

    private void verifyLogContentsOnFailure(String errorMessage, String country, StatisticsOperation... precedingOperations) {
        AuthenticationType authenticationType = AuthenticationType.eIDAS;

        Matcher<String>[] events = new Matcher[precedingOperations.length + 1];
        for (int i = 0; i < precedingOperations.length; ++i) {
            events[i] = org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType + "/" + country, precedingOperations[i]));
        }
        events[precedingOperations.length] = org.hamcrest.Matchers.containsString(
                String.format(";openIdDemo;%s;%s;%s", authenticationType + "/" + country, StatisticsOperation.ERROR, errorMessage)
        );
        SimpleTestAppender.verifyLogEventsExistInOrder(events);
    }


    private MockRequestContext getMockRequestContext(Map<String, String> requestParameters, PreAuthenticationCredential credential) {
        final MockRequestContext mockRequestContext = super.getMockRequestContext(requestParameters);
        ((MockExternalContext) mockRequestContext.getExternalContext()).setNativeResponse(
                new MockHttpServletResponse()
        );

        if (credential != null) {
            mockRequestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                    "credential", credential
            );
        }

        return mockRequestContext;
    }

    private void setAuthenticatorMockUpForAuthentication(final String country, final LevelOfAssurance loa, final String result) throws Exception {
        Mockito.doThrow(new IllegalArgumentException("Invalid input arguments to EidasAuthenticator.authenticate()"))
                .when(authenticatorMock).authenticate(Mockito.any(), Mockito.any(), Mockito.any());

        Mockito.doReturn(result.getBytes(StandardCharsets.UTF_8)).when(authenticatorMock).authenticate(
                (country != null) ? Mockito.eq(country) : Mockito.isNull(String.class),
                Mockito.matches(CommonConstants.UUID_REGEX),
                (loa != null) ? Mockito.eq(loa) : Mockito.isNull(LevelOfAssurance.class)
        );
    }

    private void verifyResponseResult(final MockRequestContext context, final String result) {
        Assert.assertArrayEquals(result.getBytes(StandardCharsets.UTF_8),
                ((MockHttpServletResponse) context.getExternalContext().getNativeResponse()).getContentAsByteArray()
        );
    }

    private String createMockAuthenticationResultString() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("PersonIdentifier", "EE/EE/" + MOCK_PERSON_IDENTIFIER);
        attributes.put("FirstName", MOCK_FIRST_NAME);
        attributes.put("FamilyName", MOCK_LAST_NAME);
        attributes.put("DateOfBirth", MOCK_DATE_OF_BIRTH);

        EidasAuthenticationResult authenticationResult = new EidasAuthenticationResult();
        authenticationResult.setAttributes(attributes);
        authenticationResult.setLevelOfAssurance("http://eidas.europa.eu/LoA/substantial");

        try {
            return new ObjectMapper().writeValueAsString(authenticationResult);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyResourcesAreCleanedUp(RequestContext requestContext) {
        Assert.assertNull("Should not contain credential after failure",requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential"));
        Assert.assertNull("Service not deleted",requestContext.getFlowScope().get("service"));
        Assert.assertNull("RelayState not deleted", requestContext.getExternalContext().getSessionMap().get("relayState"));
    }
}
