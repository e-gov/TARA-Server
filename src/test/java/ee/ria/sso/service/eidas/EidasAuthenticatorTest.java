package ee.ria.sso.service.eidas;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.logging.CorrelationIdUtil;
import ee.ria.sso.logging.CorrelationIdUtilTest;
import org.apache.http.HttpStatus;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class EidasAuthenticatorTest {

    private static final String MOCK_COUNTRY_CODE = "EE";
    private static final String MOCK_RELAY_STATE = "mock-relayState-value";
    private static final String MOCK_REQUEST_ID = "mockRequestIdValue";
    private static final String MOCK_CORRELATION_ID = "mockCorrelationIdValue";

    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().dynamicPort()
    );

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private EidasAuthenticator eidasAuthenticator;

    @BeforeClass
    public static void setUpServer() {
        wireMockServer.start();
    }

    @AfterClass
    public static void tearDownServer() {
        wireMockServer.stop();
    }

    @Before
    public void setUp() {
        EidasConfigurationProvider configurationProvider = new EidasConfigurationProvider();
        configurationProvider.setServiceUrl("http://localhost:" + wireMockServer.port());
        eidasAuthenticator = new EidasAuthenticator(configurationProvider);
    }

    @After
    public void cleanUp() throws IOException {
        eidasAuthenticator.cleanUp();
        eidasAuthenticator = null;
    }

    @Test
    public void authenticateShouldFailWhenServerRespondsUnauthorized() throws IOException {
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo(MOCK_COUNTRY_CODE))
                .withQueryParam("RelayState", WireMock.equalTo(MOCK_RELAY_STATE))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_UNAUTHORIZED))
        );

        expectedEx.expect(EidasAuthenticationFailedException.class);
        eidasAuthenticator.authenticate(MOCK_COUNTRY_CODE, MOCK_RELAY_STATE, null);
    }

    @Test
    public void authenticateShouldFailWhenServerRespondsInternalError() throws IOException {
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo(MOCK_COUNTRY_CODE))
                .withQueryParam("RelayState", WireMock.equalTo(MOCK_RELAY_STATE))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR))
        );

        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("eIDAS-Client responded with 500 HTTP status code");
        eidasAuthenticator.authenticate(MOCK_COUNTRY_CODE, MOCK_RELAY_STATE, null);
    }

    @Test
    public void authenticateShouldSucceedWithCountryAndRelayState() throws IOException {
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo(MOCK_COUNTRY_CODE))
                .withQueryParam("RelayState", WireMock.equalTo(MOCK_RELAY_STATE))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody("OK"))
        );

        byte[] result = eidasAuthenticator.authenticate(MOCK_COUNTRY_CODE, MOCK_RELAY_STATE, null);
        Assert.assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), result);
    }

    @Test
    public void authenticateShouldSucceedWithCountryAndRelayStateAndLoa() throws IOException {
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo(MOCK_COUNTRY_CODE))
                .withQueryParam("RelayState", WireMock.equalTo(MOCK_RELAY_STATE))
                .withQueryParam("LoA", WireMock.equalTo(LevelOfAssurance.SUBSTANTIAL.getAcrName().toUpperCase()))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody("OK"))
        );

        byte[] result = eidasAuthenticator.authenticate(MOCK_COUNTRY_CODE, MOCK_RELAY_STATE, LevelOfAssurance.SUBSTANTIAL);
        Assert.assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), result);
    }

    @Test
    public void authenticateShouldSucceedWithCorrelationHeaders() throws IOException {
        wireMockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/login"))
                .withQueryParam("Country", WireMock.equalTo(MOCK_COUNTRY_CODE))
                .withQueryParam("RelayState", WireMock.equalTo(MOCK_RELAY_STATE))
                .withHeader(CorrelationIdUtil.REQUEST_ID_HEADER, WireMock.equalTo(MOCK_REQUEST_ID))
                .withHeader(CorrelationIdUtil.CORRELATION_ID_HEADER, WireMock.equalTo(MOCK_CORRELATION_ID))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody("OK"))
        );

        try {
            CorrelationIdUtilTest.setMdcCorrelationValues(MOCK_REQUEST_ID, MOCK_CORRELATION_ID);
            byte[] result = eidasAuthenticator.authenticate(MOCK_COUNTRY_CODE, MOCK_RELAY_STATE, null);
            Assert.assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), result);
        } finally {
            MDC.clear();
        }
    }

    @Test
    public void getAuthenticationResultShouldFailWhenServerRespondsUnauthorized() throws IOException {
        wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/returnUrl"))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_UNAUTHORIZED))
        );

        expectedEx.expect(EidasAuthenticationFailedException.class);
        eidasAuthenticator.getAuthenticationResult(new MockHttpServletRequest());
    }

    @Test
    public void getAuthenticationResultShouldFailWhenServerRespondsInternalError() throws IOException {
        wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/returnUrl"))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR))
        );

        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("eIDAS-Client responded with 500 HTTP status code");
        eidasAuthenticator.getAuthenticationResult(new MockHttpServletRequest());
    }

    @Test
    public void getAuthenticationResultShouldSucceed() throws IOException {
        wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/returnUrl"))
                .withRequestBody(WireMock.equalTo("mockReqParamName=mockReqParamValue"))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody("OK"))
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("mockReqParamName", "mockReqParamValue");

        byte[] result = eidasAuthenticator.getAuthenticationResult(request);
        Assert.assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), result);
    }

    @Test
    public void getAuthenticationResultShouldSucceedWithCorrelationHeaders() throws IOException {
        wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/returnUrl"))
                .withHeader(CorrelationIdUtil.REQUEST_ID_HEADER, WireMock.equalTo(MOCK_REQUEST_ID))
                .withHeader(CorrelationIdUtil.CORRELATION_ID_HEADER, WireMock.equalTo(MOCK_CORRELATION_ID))
                .willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody("OK"))
        );

        try {
            CorrelationIdUtilTest.setMdcCorrelationValues(MOCK_REQUEST_ID, MOCK_CORRELATION_ID);
            byte[] result = eidasAuthenticator.getAuthenticationResult(new MockHttpServletRequest());
            Assert.assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), result);
        } finally {
            MDC.clear();
        }
    }

}
