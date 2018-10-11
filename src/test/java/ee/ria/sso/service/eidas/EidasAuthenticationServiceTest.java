package ee.ria.sso.service.eidas;

import ee.ria.sso.CommonConstants;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.config.eidas.TestEidasConfiguration;
import ee.ria.sso.model.AuthenticationResult;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matcher;
import org.junit.*;
import org.mockito.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;
import wiremock.com.fasterxml.jackson.core.JsonProcessingException;
import wiremock.com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@ContextConfiguration(
        classes = TestEidasConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class EidasAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String MOCK_PERSON_IDENTIFIER = "60001019906";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_DATE_OF_BIRTH = "2000-01-01";

    @Autowired
    private EidasConfigurationProvider configurationProvider;

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @Autowired
    private StatisticsHandler statistics;

    @Mock
    private EidasAuthenticator authenticatorMock;

    private EidasAuthenticationService authenticationService;

    @Before
    public void setUp() {
        Mockito.reset(authenticatorMock);
        authenticationService = new EidasAuthenticationService(messageSource, statistics, authenticatorMock);
    }

    @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByEidasWithoutLoaShouldSucceedAndWriteAuthenticatorResponse() throws Exception {
        TaraCredential credential = new TaraCredential();
        credential.setCountry("someCountry");

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        setAuthenticatorMockUpForAuthentication("someCountry", null,"someAuthenticationResult");

        Event event = this.authenticationService.startLoginByEidas(requestContext);

        Assert.assertEquals("success", event.getId());
        this.verifyResponseResult(requestContext, "someAuthenticationResult");
        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    @Test
    public void startLoginByEidasWithLoaShouldSucceedAndWriteAuthenticatorResponse() throws Exception {
        TaraCredential credential = new TaraCredential();
        credential.setCountry("someCountry");

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        requestContext.getExternalContext().getSessionMap().put(Constants.TARA_OIDC_SESSION_LoA, LevelOfAssurance.HIGH);
        setAuthenticatorMockUpForAuthentication("someCountry", LevelOfAssurance.HIGH,"someAuthenticationResult");

        Event event = this.authenticationService.startLoginByEidas(requestContext);

        Assert.assertEquals("success", event.getId());
        this.verifyResponseResult(requestContext, "someAuthenticationResult");
        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    @Test
    public void startLoginByEidasShouldFailWhenEidasAuthenticatorThrowsException() throws Exception {
        TaraCredential credential = new TaraCredential();
        credential.setCountry("someCountry");

        MockRequestContext requestContext = this.getMockRequestContext(null, credential);
        Mockito.doThrow(new IOException("Something went wrong in EidasAuthenticator.authenticate()"))
                .when(authenticatorMock).authenticate(Mockito.any(), Mockito.any(), Mockito.any());

        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.io.IOException: Something went wrong in EidasAuthenticator.authenticate()");

        try {
            Event event = this.authenticationService.startLoginByEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure(
                    "Something went wrong in EidasAuthenticator.authenticate()",
                    StatisticsOperation.START_AUTH);
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    protected MockRequestContext getMockRequestContext(Map<String, String> requestParameters, TaraCredential credential) {
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

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPresent() {
        RequestContext requestContext = this.getMockRequestContext(null);

        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.IllegalStateException: SAML response's relay state (null) not found among previously stored relay states!");

        try {
            Event event = this.authenticationService.checkLoginForEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure("SAML response's relay state (null) not found among previously stored relay states!");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPreviouslyStored() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.IllegalStateException: SAML response's relay state (someRelayState) not found among previously stored relay states!");

        RequestContext requestContext = this.getMockRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", "someRelayState");

        try {
            Event event = this.authenticationService.checkLoginForEidas(requestContext);
        } catch (Exception e) {
            verifyLogContentsOnFailure("SAML response's relay state (someRelayState) not found among previously stored relay states!");
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

        setAuthenticatorMockUpForAuthenticationResultRetrieval(requestContext,
                createMockAuthenticationResultString());

        Event event = this.authenticationService.checkLoginForEidas(requestContext);
        Assert.assertEquals("success", event.getId());

        validateUserCredential((TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential"));
        Assert.assertEquals(serviceValueStoredAsRelayState, requestContext.getFlowScope().get("service"));
        Assert.assertNull("RelayState not deleted after successful verification", requestContext.getExternalContext().getSessionMap().get("relayState"));

        this.verifyLogContents(StatisticsOperation.SUCCESSFUL_AUTH);
    }

    private String createMockAuthenticationResultString() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("PersonIdentifier", "EE/EE/" + MOCK_PERSON_IDENTIFIER);
        attributes.put("FirstName", MOCK_FIRST_NAME);
        attributes.put("FamilyName", MOCK_LAST_NAME);
        attributes.put("DateOfBirth", MOCK_DATE_OF_BIRTH);

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAttributes(attributes);

        try {
            return new ObjectMapper().writeValueAsString(authenticationResult);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private void setAuthenticatorMockUpForAuthenticationResultRetrieval(final RequestContext context, final String result) throws Exception {
        Mockito.doThrow(new IllegalArgumentException("Invalid input arguments to EidasAuthenticator.getAuthenticationResult()"))
                .when(authenticatorMock).getAuthenticationResult(Mockito.any());

        Mockito.doReturn(result.getBytes(StandardCharsets.UTF_8)).when(authenticatorMock).getAuthenticationResult(
                Mockito.eq((HttpServletRequest) context.getExternalContext().getNativeRequest())
        );
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.eIDAS, credential.getType());
        Assert.assertEquals("EE" + MOCK_PERSON_IDENTIFIER, credential.getId());
        Assert.assertEquals(MOCK_FIRST_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_LAST_NAME, credential.getLastName());
        Assert.assertEquals(MOCK_DATE_OF_BIRTH, credential.getDateOfBirth());
    }

    private void verifyLogContents(StatisticsOperation statisticsOperation) {
        AuthenticationType authenticationType = AuthenticationType.eIDAS;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, statisticsOperation))
        );
    }

    private void verifyLogContentsOnFailure(String errorMessage, StatisticsOperation... precedingOperations) {
        AuthenticationType authenticationType = AuthenticationType.eIDAS;

        Matcher<String>[] events = new Matcher[precedingOperations.length + 1];
        for (int i = 0; i < precedingOperations.length; ++i) {
            events[i] = org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, precedingOperations[i]));
        }
        events[precedingOperations.length] = org.hamcrest.Matchers.containsString(
                String.format(";openIdDemo;%s;%s;%s", authenticationType, StatisticsOperation.ERROR, errorMessage)
        );
        SimpleTestAppender.verifyLogEventsExistInOrder(events);
    }

}
