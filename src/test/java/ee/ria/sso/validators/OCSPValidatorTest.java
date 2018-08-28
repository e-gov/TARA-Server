package ee.ria.sso.validators;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.apache.axis.encoding.Base64;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

@RunWith(SpringJUnit4ClassRunner.class)
public class OCSPValidatorTest {

    private static final int OCSP_SERVER_PORT = 7171;
    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().port(OCSP_SERVER_PORT)
    );

    private static final String MOCK_OCSP_URL = String.format("http://localhost:%d/ocsp", OCSP_SERVER_PORT);
    private static final String MOCK_OCSP_RESPONSE_BASE64 = "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";
    private static final String MOCK_ISSUER_CERT_PATH = "classpath:ocsp/TEST_of_EID-SK_2016.crt";
    private static final String MOCK_USER_CERT_PATH = "classpath:id-card/47101010033.pem";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private ResourceLoader resourceLoader;

    private OCSPValidator ocspValidator;

    @BeforeClass
    public static void setUp() {
        wireMockServer.start();
    }

    @AfterClass
    public static void tearDown() {
        wireMockServer.stop();
    }

    @Before
    public void setUpTest() {
        ocspValidator = new OCSPValidator();
    }

    @Test
    public void validateShouldThrowExceptionWhenUserCertIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);

        expectedEx.expect(NullPointerException.class);
        ocspValidator.validate(null, issuerCert, MOCK_OCSP_URL, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenIssuerCertIsMissing() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(NullPointerException.class);
        ocspValidator.validate(userCert, null, MOCK_OCSP_URL, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspRespondsNotOk() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        wireMockServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(500))
        );

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP request failed with status code 500!");

        ocspValidator.validate(userCert, issuerCert, MOCK_OCSP_URL, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseValidationCertMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(mockOcspResponse());

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP cert not found from setup");

        ocspValidator.validate(userCert, issuerCert, MOCK_OCSP_URL, Collections.emptyMap());
    }

    private X509Certificate loadCertificateFromResource(String resourcePath) throws CertificateException, IOException {
        Resource resource = resourceLoader.getResource(resourcePath);
        if (!resource.exists()) {
            throw new IllegalArgumentException("Could not find file " + resourcePath);
        }

        try (InputStream inputStream = resource.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

    private void updateWiremockOcspResponse(OCSPResp response) throws IOException {
        wireMockServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/ocsp-request")
                        .withBody(response.getEncoded())
                )
        );
    }

    private OCSPResp mockOcspResponse() throws IOException {
        byte[] responseBytes = Base64.decode(MOCK_OCSP_RESPONSE_BASE64);
        return new OCSPResp(responseBytes);
    }

}
