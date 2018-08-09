package ee.ria.sso.service.eidas;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.config.eidas.TestEidasConfiguration;
import ee.ria.sso.model.AuthenticationResult;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.junit.*;
import org.mockito.AdditionalMatchers;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import wiremock.com.fasterxml.jackson.core.JsonProcessingException;
import wiremock.com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;

@ContextConfiguration(
        classes = TestEidasConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class EidasAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String UUID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$";
    private static final String MOCK_PERSON_IDENTIFIER = "60001019906";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_DATE_OF_BIRTH = "2000-01-01";

    private static final int EIDAS_CLIENT_PORT = 7171;
    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().port(EIDAS_CLIENT_PORT)
    );

    @Autowired
    private EidasConfigurationProvider configurationProvider;

    @Autowired
    private EidasAuthenticationService authenticationService;

    @BeforeClass
    public static void setUp() {
        wireMockServer.start();
    }

    @AfterClass
    public static void tearDown() {
        wireMockServer.stop();
    }

    @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByEidasShouldFailWhenNoCredentialPresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.NullPointerException");

        Event event = this.authenticationService.startLoginByEidas(this.getRequestContext(null));
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByEidasShouldFailWhenNoCountryPresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.IllegalStateException: eIDAS-Client responded with 400 HTTP status code");

        TaraCredential credential = new TaraCredential();
        credential.setCountry(null);

        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo("null"))
                .willReturn(WireMock.aResponse().withStatus(400).withBody("BAD REQUEST"))
        );

        try {
            Event event = this.authenticationService.startLoginByEidas(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, "eIDAS-Client responded with 400 HTTP status code");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByEidasShouldSucceed() {
        TaraCredential credential = new TaraCredential();
        credential.setCountry("EE");

        RequestContext requestContext = this.getRequestContext(null);
        MockServletOutputStream stream = addMockHttpServletResponseToRequestContextExternalContext(requestContext);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        String eidasResponse = "OK";
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo("EE"))
                .withQueryParam("RelayState", WireMock.matching(UUID_REGEX))
                .willReturn(WireMock.aResponse().withStatus(200).withBody(eidasResponse))
        );
        Event event = this.authenticationService.startLoginByEidas(requestContext);

        Assert.assertEquals("success", event.getId());
        Assert.assertArrayEquals(eidasResponse.getBytes(StandardCharsets.UTF_8), stream.getWrittenContent());
        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    private MockServletOutputStream addMockHttpServletResponseToRequestContextExternalContext(RequestContext requestContext) {
        HttpServletResponse mockHttpServletResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.doThrow(new IllegalArgumentException()).when(mockHttpServletResponse).setContentType(
                AdditionalMatchers.not(Matchers.eq("text/html; charset=UTF-8"))
        );

        MockServletOutputStream mockOutputStream = new MockServletOutputStream();

        try {
            Mockito.when(mockHttpServletResponse.getOutputStream()).thenReturn(mockOutputStream);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        MockExternalContext mockExternalContext = (MockExternalContext) requestContext.getExternalContext();
        mockExternalContext.setNativeResponse(mockHttpServletResponse);

        return mockOutputStream;
    }

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.RuntimeException: SAML response's relay state (null) not found among previously stored relay states!");

        RequestContext requestContext = this.getRequestContext(null);
        Event event = this.authenticationService.checkLoginForEidas(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasShouldFailWhenRelayStateNotPreviouslyStored() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.RuntimeException: SAML response's relay state (someRelayState) not found among previously stored relay states!");

        RequestContext requestContext = this.getRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", "someRelayState");

        try {
            Event event = this.authenticationService.checkLoginForEidas(requestContext);
        } catch (Exception e) {
            SimpleTestAppender.verifyLogEventsExistInOrder(
                    org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", AuthenticationType.eIDAS, StatisticsOperation.ERROR,
                            "SAML response's relay state (someRelayState) not found among previously stored relay states!"))
            );
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void checkLoginForEidasSucceeds() {
        String relayState = UUID.randomUUID().toString();
        RequestContext requestContext = this.getRequestContext(null);
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("SAMLResponse", "someSamlResponse");
        ((MockHttpServletRequest) (requestContext.getExternalContext().getNativeRequest()))
                .addParameter("RelayState", relayState);

        String serviceValueStoredAsRelayState = "someServiceValueStoreadAsRelayState";
        requestContext.getExternalContext().getSessionMap().put(relayState, serviceValueStoredAsRelayState);

        String eidasResponse = createMockAuthenticationResultString();
        wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/returnUrl"))
                .withRequestBody(WireMock.matching(".*SAMLResponse=someSamlResponse.*"))
                .willReturn(WireMock.aResponse().withStatus(200).withBody(eidasResponse))
        );

        Event event = this.authenticationService.checkLoginForEidas(requestContext);
        Assert.assertEquals("success", event.getId());

        validateUserCredential((TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential"));
        Assert.assertEquals(serviceValueStoredAsRelayState, requestContext.getFlowScope().get("service"));

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

    private void verifyLogContentsOnFailure(StatisticsOperation precedingOperation, String errorMessage) {
        AuthenticationType authenticationType = AuthenticationType.eIDAS;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, precedingOperation)),
                org.hamcrest.Matchers.containsString(String.format(";openIdDemo;%s;%s;%s", authenticationType, StatisticsOperation.ERROR, errorMessage))
        );
    }

}
