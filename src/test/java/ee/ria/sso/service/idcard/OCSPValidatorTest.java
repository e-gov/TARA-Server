package ee.ria.sso.service.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import ee.ria.sso.Constants;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;
import static com.github.tomakehurst.wiremock.client.WireMock.binaryEqualTo;

@RunWith(SpringJUnit4ClassRunner.class)
public class OCSPValidatorTest {

    private static final OcspResponseTransformer ocspResponseTransformer = new OcspResponseTransformer();
    private static final WireMockServer mockOcspServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().dynamicPort().extensions(ocspResponseTransformer)
    );
    private static final WireMockServer mockFallbackOcspServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().dynamicPort().extensions(ocspResponseTransformer)
    );


    private static final String MOCK_ISSUER_CERT_2011_PATH = "classpath:ocsp/TEST_of_ESTEID-SK_2011.crt";
    private static final String MOCK_ISSUER_CERT_2015_PATH = "classpath:ocsp/TEST_of_ESTEID-SK_2015.crt";
    private static final String MOCK_ISSUER_CERT_2018_PATH = "classpath:ocsp/TEST_of_ESTEID2018.crt";

    private static final String MOCK_USER_CERT_2011_PATH = "classpath:id-card/48812040138(TEST_of_ESTEID-SK_2011).pem";
    private static final String MOCK_USER_CERT_2015_PATH = "classpath:id-card/47101010033(TEST_of_ESTEID-SK_2015).pem";
    private static final String MOCK_USER_CERT_2018_PATH = "classpath:id-card/38001085718(TEST_of_ESTEID2018).pem";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private ResourceLoader resourceLoader;

    @Mock
    private Map<String, X509Certificate> trustedCertificates;
    @Mock
    private OCSPConfigurationResolver ocspConfigurationResolver;


    @InjectMocks
    private OCSPValidator ocspValidator;

    private IDCardConfigurationProvider.Ocsp ocspConfiguration;
    private KeyPair responderKeys;
    private X509Certificate responderCert;

    @BeforeClass
    public static void setUp() {
        mockOcspServer.start();
        mockFallbackOcspServer.start();
    }

    @AfterClass
    public static void tearDown() {
        mockOcspServer.stop();
        mockFallbackOcspServer.stop();
    }

    @Before
    public void setUpTest() throws Exception {
        MDC.clear();
        ocspValidator = new OCSPValidator(trustedCertificates, ocspConfigurationResolver);

        ocspConfiguration = getMockOcspConfiguration(
                Arrays.asList("TEST of ESTEID-SK 2015"),
                String.format("http://localhost:%d/ocsp", mockOcspServer.port()),
                "TEST of SK OCSP RESPONDER 2011", false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(Arrays.asList(ocspConfiguration));

        Mockito.when(trustedCertificates.get("TEST of ESTEID2018")).thenReturn(loadCertificateFromResource(MOCK_ISSUER_CERT_2018_PATH));
        Mockito.when(trustedCertificates.get("TEST of ESTEID-SK 2015")).thenReturn(loadCertificateFromResource(MOCK_ISSUER_CERT_2015_PATH));
        Mockito.when(trustedCertificates.get("TEST of ESTEID-SK 2011")).thenReturn(loadCertificateFromResource(MOCK_ISSUER_CERT_2011_PATH));

        responderCert = generateOcspResponderCertificate(
                "C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=ESTEID2018 AIA OCSP RESPONDER 201903,E=pki@sk.ee",
                responderKeys, keyPairGenerator.generateKeyPair(),
                "CN=MOCK CA").getCertificate();
        Mockito.when(trustedCertificates.get("TEST of SK OCSP RESPONDER 2011")).thenReturn(responderCert);
    }

    @Test
    public void checkCertShouldThrowExceptionWhenUserCertIsMissing() throws Exception {
        try {
            ocspValidator.checkCert(null);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
            assertThat(e.getMessage(), containsString("User certificate cannot be null!"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenIssuerCertIsNotTrusted() throws Exception {
        Mockito.when(trustedCertificates.get("TEST of ESTEID-SK 2015")).thenReturn(null);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Issuer certificate with CN 'TEST of ESTEID-SK 2015' is not a trusted certificate!"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspConfigurationIsMissing() throws Exception {
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(null);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
            assertThat(e.getMessage(), containsString("At least one OCSP configuration must be present"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspRespondsNotOk() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        mockOcspServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(500))
        );

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(OCSPServiceNotAvailableException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Service returned HTTP status code 500"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseHasInvalidContentType() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        mockOcspServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse()
                        .withTransformerParameter("ignore", true)
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody("<html><body>Hello world!</body></html>")
                )
        );

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(OCSPServiceNotAvailableException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Response Content-Type header is missing or invalid. Expected: 'application/ocsp-response', actual: text/html"));
            assertMdcContent(null);
    }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseIsMissingBody() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        mockOcspServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse()
                        .withTransformerParameter("ignore", true)
                        .withStatus(200)
                        .withHeader("Content-Type", "application/ocsp-response")
                        .withBody(Hex.decodeHex("30030a0100"))
                )
        );

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Invalid OCSP response! OCSP response object bytes could not be read!"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseValidationCertMissing() throws Exception {
        Mockito.when(trustedCertificates.get("TEST of SK OCSP RESPONDER 2011")).thenReturn(null);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP validation failed: Certificate with CN: 'TEST of SK OCSP RESPONDER 2011' is not trusted! Please check your configuration!"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseNonceIsMissingAndNonceRequiredByConf() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);
        ocspResponseTransformer.setNonceResolver(nonce -> null);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("No nonce found in OCSP response"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseNonceIsInvalid() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);
        ocspResponseTransformer.setNonceResolver(nonce -> {
            return new DEROctetString(new byte[]{ 0 });
        });

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Invalid OCSP response nonce"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseThisUpdateIsTooOld() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);
        ocspResponseTransformer.setThisUpdateProvider(() -> {
            final Instant instant = Instant.now()
                    .minusSeconds(ocspConfiguration.getAcceptedClockSkewInSeconds())
                    .minusSeconds(ocspConfiguration.getResponseLifetimeInSeconds())
                    .minusSeconds(1L);
            return Date.from(instant);
        });

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP response was older than accepted"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseThisUpdateIsInTheFuture() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);
        ocspResponseTransformer.setThisUpdateProvider(() -> {
            final Instant instant = Instant.now()
                    .plusSeconds(ocspConfiguration.getAcceptedClockSkewInSeconds())
                    .plusSeconds(5L);
            return Date.from(instant);
        });

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP response cannot be produced in the future"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseSignatureIsInvalid() throws Exception {
        Mockito.when(trustedCertificates.get("TEST of SK OCSP RESPONDER 2011")).thenReturn(
                generateOcspResponderCertificate(
                        "C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee",
                        KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair(),
                        KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair(),
                        "CN=MOCK CA").getCertificate()
        );
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP response signature is not valid"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseDoesNotContainCertificateReferencedByRespIdUsingImplicitConfiguration() throws Exception {
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(
                Arrays.asList("TEST of ESTEID2018"),
                String.format("http://localhost:%d/ocsp", mockOcspServer.port()),
                null, false);
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration
                )
        );

        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2018_PATH);

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("C=EE,O=TEST,OU=OCSP,CN=TEST,E=pki@sk.ee")
                .ocspConf(ocspConfiguration)
                .responderCertificate(responderCert).build());

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP validation failed: Invalid OCSP response! " +
                    "Responder ID in response contains value: TEST, but there was " +
                    "no cert provided with this CN in the response."));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseDoesNotContainCertificateReferencedByRespId() throws Exception {
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(
                Arrays.asList("TEST of ESTEID-SK 2015"),
                String.format("http://localhost:%d/ocsp", mockOcspServer.port()),
                null, false);
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration
                )
        );

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("C=EE,O=TEST,OU=TEST,CN=TEST,E=pki@test.ee")
                .ocspConf(ocspConfiguration)
                .responderCertificate(responderCert).build());

        try {
            ocspValidator.checkCert(loadCertificateFromResource(MOCK_USER_CERT_2015_PATH));
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Invalid OCSP response! Responder ID in response contains value: TEST, but there was no cert provided with this CN in the response."));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenCertificateStatusIsRevoked() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, new RevokedStatus(
                new Date(), CRLReason.unspecified
        ), ocspConfiguration);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(OCSPValidationException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Invalid certificate status <REVOKED> received"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenCertificateStatusIsUnknown() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        setUpMockOcspResponse(OCSPResp.SUCCESSFUL, new UnknownStatus(), ocspConfiguration);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(OCSPValidationException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Invalid certificate status <UNKNOWN> received"));
            assertMdcContent(ocspConfiguration.getUrl());
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenAiaOcspResponderIssuerNotTheSameAsUserCertIssuer() throws Exception {

        String ocspUrl = String.format("http://localhost:%d/ocsp", mockOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(
                Arrays.asList("TEST of ESTEID2018"),
                ocspUrl,
                null, false);
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration
                )
        );

        KeyPair certKeys = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();
        X509Certificate ocspResponseSignCert = generateOcspResponderCertificate("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=ESTEID2018 AIA OCSP RESPONDER 201903,E=pki@sk.ee", certKeys, responderKeys, "CN=MOCK CA").getCertificate();
        Mockito.when(trustedCertificates.get("MOCK CA")).thenReturn(loadCertificateFromResource(MOCK_ISSUER_CERT_2011_PATH));

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=ESTEID2018 AIA OCSP RESPONDER 201903,E=pki@sk.ee")
                .ocspConf(this.ocspConfiguration)
                .responderCertificate(
                        ocspResponseSignCert
                ).build());
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2018_PATH);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP validation failed: In case of AIA OCSP, the OCSP responder certificate " +
                    "must be issued by the authority that issued the user certificate. " +
                    "Expected issuer: 'CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE', " +
                    "but the OCSP responder signing certificate " +
                    "was issued by 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE'"));
            assertMdcContent(ocspUrl);
        }

    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspTimesOut() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .delay(20000)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .ocspConf(ocspConfiguration)
                .responderCertificate(responderCert).build());

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(OCSPServiceNotAvailableException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP not available: http://localhost:"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenNoOcspConfigurationCouldBeResolved() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2011_PATH);

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(null);

        try {
            ocspValidator.checkCert(userCert);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
            assertThat(e.getMessage(), containsString("At least one OCSP configuration must be present"));
            assertMdcContent(null);
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenOcspResponseCertDoesNotContainCn() throws Exception {
        try {
            setUpMockOcspResponse(MockOcspResponseParams.builder()
                    .ocspServer(mockOcspServer)
                    .responseStatus(OCSPResp.SUCCESSFUL)
                    .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                    .responseId("C=\"EE\"")
                    .ocspConf(ocspConfiguration)
                    .responderCertificate(
                            generateOcspResponderCertificate("C=\"EE\"", responderKeys, responderKeys, "CN=MOCK CA").getCertificate()
                    ).build());

            ocspValidator.checkCert(loadCertificateFromResource(MOCK_USER_CERT_2015_PATH));
            fail("Should not reach this!");
        } catch (Exception e) {
            assertEquals(IllegalStateException.class, e.getClass());
            assertThat(e.getMessage(), containsString("OCSP validation failed: Unable to find responder CN from OCSP response"));
            assertMdcContent( String.format("http://localhost:%d/ocsp", mockOcspServer.port()));
        }
    }

    @Test
    public void checkCertShouldThrowExceptionWhenUserCertNotSignedByTrustedCa() throws Exception {
        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("Failed to verify user certificate");

        Mockito.when(trustedCertificates.get("MOCK CA")).thenReturn(loadCertificateFromResource(MOCK_ISSUER_CERT_2011_PATH));
        ocspValidator.checkCert(generateOcspResponderCertificate("CN=\"TEST\"", responderKeys, responderKeys, "CN=MOCK CA").getCertificate());
    }

    @Test
    public void checkCertShouldSucceedWithExplicitResponderCert() throws Exception {
        String ocspUrl = String.format("http://localhost:%d/ocsp", mockOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(Arrays.asList("TEST of ESTEID-SK 2015"),
                        ocspUrl,
                        "TEST of SK OCSP RESPONDER 2011",
                        true);

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(ocspConfiguration)
        );

        byte[] expectedOcspRequest = Base64.getDecoder().decode("MG0wazBpMGcwZTANBglghkgBZQMEAgEFAAQgQTfFmz1j3fzLrJqT3Ikf23e/0r75XTnlb2QmIVzFBZwEIClUf0hIboz4kAIxZJXZqAhySiadWFWwWJts7b8Lra2MAhAVGSYAmGbQQVncumVvnG27");
        setUpMockOcspResponse(expectedOcspRequest, OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD, ocspConfiguration);

        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_2015_PATH);
        ocspValidator.checkCert(userCert);
        assertMdcContent(ocspUrl);
    }

    @Test
    public void checkCertShouldSucceedWhenNoExplicitResponderCertConfiguredAndSignerCertNotInTruststore() throws Exception {
        String ocspUrl = String.format("http://localhost:%d/ocsp", mockOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(Arrays.asList("TEST of ESTEID2018"), ocspUrl, null, false);
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration
                )
        );

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();

        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=\"MOCK OCSP RESPONDER\", C=EE", certKeyPair, responderKeys, "CN=MOCK CA").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        Mockito.when(trustedCertificates.get("MOCK CA")).thenReturn(generateCertificate(responderKeys, "CN=\"MOCK_CA\""));

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("CN=\"MOCK OCSP RESPONDER\"")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build());

        X509Certificate userCert = generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE", responderKeys, "CN=MOCK CA").getCertificate();

        new OCSPValidator(trustedCertificates, ocspConfigurationResolver).checkCert(userCert);

        assertMdcContent(ocspUrl);
    }

    @Test
    public void checkCertShouldSucceedWhenNoExplicitResponderCertConfiguredAndSignerCertFoundInTruststore() throws Exception {
        String ocspUrl = String.format("http://localhost:%d/ocsp", mockOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspConfiguration = getMockOcspConfiguration(Arrays.asList("TEST of ESTEID2018"), ocspUrl, null, false);
        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration
                )
        );

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();

        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=\"MOCK OCSP RESPONDER\", C=EE", certKeyPair, responderKeys, "CN=MOCK CA").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        Mockito.when(trustedCertificates.get("MOCK CA")).thenReturn(generateCertificate(responderKeys, "CN=\"MOCK_CA\""));
        Mockito.when(trustedCertificates.get("MOCK OCSP RESPONDER")).thenReturn(ocspResponderCert);

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("CN=\"MOCK OCSP RESPONDER\"")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build());

        X509Certificate userCert = generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE", responderKeys, "CN=MOCK CA").getCertificate();

        new OCSPValidator(trustedCertificates, ocspConfigurationResolver).checkCert(userCert);

        assertMdcContent(ocspUrl);
    }

    @Test
    public void checkCertShouldSucceedWhenPrimaryOcspFailsWithTimeoutButFallbackResponds() throws Exception {
        String fallbackOcspUrl = String.format("http://localhost:%d/ocsp", mockFallbackOcspServer.port());

        IDCardConfigurationProvider.Ocsp ocspFallbackConfiguration = getMockOcspConfiguration(
                Arrays.asList("SOME TRUSTED ISSUER", "TEST of ESTEID-SK 2015", "SOME OTHER TRUSTED ISSUER"),
                fallbackOcspUrl, "TEST of SK OCSP RESPONDER 2011", false
        );

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration,
                        ocspFallbackConfiguration
                )
        );

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .delay(20000)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .ocspConf(ocspConfiguration)
                .responderCertificate(responderCert).build());

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockFallbackOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .delay(0)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .ocspConf(ocspFallbackConfiguration)
                .responderCertificate(responderCert).build());


        ocspValidator.checkCert(loadCertificateFromResource(MOCK_USER_CERT_2015_PATH));

        assertMdcContent(fallbackOcspUrl);
    }

    @Test
    public void checkCertShouldSucceedWhenPrimaryOcspFailsWithHttp500ButFallbackResponds() throws Exception {

        String ocspUrl = String.format("http://localhost:%d/ocsp", mockFallbackOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspFallbackConfiguration = getMockOcspConfiguration(
                Arrays.asList("SOME TRUSTED ISSUER", "TEST of ESTEID-SK 2015", "SOME OTHER TRUSTED ISSUER"),
                ocspUrl, "TEST of SK OCSP RESPONDER 2011", false
        );

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration,
                        ocspFallbackConfiguration
                )
        );

        mockOcspServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse()
                        .withTransformerParameter("ignore", true)
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody("<html><body>Hello world!</body></html>")
                )
        );

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockFallbackOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .delay(0)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .ocspConf(ocspFallbackConfiguration)
                .responderCertificate(responderCert).build());


        ocspValidator.checkCert(loadCertificateFromResource(MOCK_USER_CERT_2015_PATH));

        assertMdcContent(ocspUrl);
    }

    @Test
    public void checkCertShouldSucceedWhenPrimaryOcspFailsWithHttp200AndWrongContentTypeButFallbackResponds() throws Exception {

        String ocspUrl = String.format("http://localhost:%d/ocsp", mockFallbackOcspServer.port());
        IDCardConfigurationProvider.Ocsp ocspFallbackConfiguration = getMockOcspConfiguration(
                Arrays.asList("SOME TRUSTED ISSUER", "TEST of ESTEID-SK 2015", "SOME OTHER TRUSTED ISSUER"),
                ocspUrl, "TEST of SK OCSP RESPONDER 2011", false
        );

        Mockito.when(ocspConfigurationResolver.resolve(Mockito.any())).thenReturn(
                Arrays.asList(
                        ocspConfiguration,
                        ocspFallbackConfiguration
                )
        );

        mockOcspServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(500))
        );

        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockFallbackOcspServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .delay(0)
                .certificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .ocspConf(ocspFallbackConfiguration)
                .responderCertificate(responderCert).build());


        ocspValidator.checkCert(loadCertificateFromResource(MOCK_USER_CERT_2015_PATH));

        assertMdcContent(ocspUrl);
    }

    private X509Certificate generateCertificate(KeyPair keyPair, String name) throws OperatorCreationException, CertIOException, CertificateException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(name);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);

        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true);
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(contentSigner));
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

    private void setUpMockOcspResponse(int responseStatus, org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus, IDCardConfigurationProvider.Ocsp ocspConfiguration) {
        setUpMockOcspResponse(null, responseStatus, certificateStatus, ocspConfiguration);
    }

    private void setUpMockOcspResponse(byte[] expectedOcspRequest, int responseStatus, org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus, IDCardConfigurationProvider.Ocsp ocspConfiguration) {
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(mockOcspServer)
                .responseStatus(responseStatus)
                .certificateStatus(certificateStatus)
                .responseId("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee")
                .responderCertificate(responderCert)
                .signatureAlgorithm("SHA256withRSA")
                .ocspConf(ocspConfiguration)
                .build(), null);
    }

    private static void setUpMockOcspResponse(MockOcspResponseParams responseParams) {
        setUpMockOcspResponse(responseParams, null);
    }

    private static void setUpMockOcspResponse(MockOcspResponseParams responseParams, byte[] expectedOcspRequest) {
        ocspResponseTransformer.setResponseStatus(responseParams.getResponseStatus());
        ocspResponseTransformer.setCertificateStatus(responseParams.getCertificateStatus());
        ocspResponseTransformer.setResponderCertificate(responseParams.getResponderCertificate());

        MappingBuilder mappingBuilder = WireMock.post("/ocsp");
        if (expectedOcspRequest != null) {
            mappingBuilder.withRequestBody(binaryEqualTo(expectedOcspRequest));
        }

        mappingBuilder.willReturn(
                WireMock.aResponse()
                .withStatus(200)
                        .withTransformerParameter("responderId", responseParams.getResponseId())
                        .withTransformerParameter("signatureAlgorithm", responseParams.getSignatureAlgorithm() == null ? "SHA256withRSA" : responseParams.getSignatureAlgorithm())
                        .withTransformerParameter("ocspConf", responseParams.getOcspConf())
                .withFixedDelay(responseParams.getDelay())
                .withHeader("Content-Type", "application/ocsp-response")
        );
        responseParams.getOcspServer().stubFor(mappingBuilder);
    }

    @Builder
    @Data
    static class MockOcspResponseParams {
        int responseStatus;
        org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus;
        int delay;
        WireMockServer ocspServer;
        String responseId;
        X509Certificate responderCertificate;
        String signatureAlgorithm;
        IDCardConfigurationProvider.Ocsp ocspConf;
    }

    private static void validateNonceDerOctetString(DEROctetString nonceDerOctetString) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(nonceDerOctetString.getOctetStream())) {
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            if (!DEROctetString.class.isInstance(asn1Primitive))
                throw new IllegalStateException("Nonce must be doubly wrapped in octet string");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to extract an octet string from nonce octet string", e);
        }
    }

    @Setter
    public static class OcspResponseTransformer extends ResponseTransformer {

        private int responseStatus;
        private CertificateStatus certificateStatus;
        private Function<DEROctetString, DEROctetString> nonceResolver;
        private Supplier<Date> thisUpdateProvider;
        private PrivateKey signerKey;
        private X509Certificate responderCertificate;

        @Override
        public Response transform(Request request, Response response, FileSource fileSource, Parameters parameters) {
            if (parameters != null && parameters.containsKey("ignore")) return response;
            if (response.getStatus() != 200) return response;
            byte[] responseBytes;

            try {
                OCSPReq ocspReq = new OCSPReq(request.getBody());

                IDCardConfigurationProvider.Ocsp ocspConf = (IDCardConfigurationProvider.Ocsp)parameters.get("ocspConf");
                DEROctetString nonce = null;
                if (!ocspConf.isNonceDisabled()) {
                    Assert.assertNotNull(ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
                    assertEquals(1, ocspReq.getRequestList().length);
                    nonce = (DEROctetString) ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue();
                    validateNonceDerOctetString(nonce);
                }

                BasicOCSPResp basicOCSPResp = mockOcspResponse(
                        ocspReq.getRequestList()[0].getCertID(),
                        this.nonceResolver.apply(nonce),
                        responderCertificate.getEncoded(),
                        parameters.getString("responderId"),
                        parameters.getString("signatureAlgorithm")
                );
                OCSPResp ocspResp = new OCSPRespBuilder().build(this.responseStatus, basicOCSPResp);

                responseBytes = ocspResp.getEncoded();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            return Response.Builder.like(response)
                    .body(responseBytes)
                    .build();
        }

        @Override
        public String getName() {
            return getClass().getSimpleName();
        }

        private BasicOCSPResp mockOcspResponse(CertificateID certificateID, DEROctetString nonce, byte[] responderCert, String responseId, String signatureAlgorithm) throws OCSPException, OperatorCreationException, IOException {
            RespID respID = new RespID(new X500Name(responseId));
            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respID);
            builder.addResponse(certificateID, this.certificateStatus,
                    this.thisUpdateProvider.get(),
                    null,
                    null
            );

            if (nonce != null) {
                Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
                builder.setResponseExtensions(new Extensions(new Extension[]{ extension }));
            }

            return builder.build(
                    new JcaContentSignerBuilder(signatureAlgorithm).build(this.signerKey),
                    new X509CertificateHolder[] {new X509CertificateHolder(responderCert)},
                    Date.from(Instant.now())
            );
        }

    }

    private IDCardConfigurationProvider.Ocsp getMockOcspConfiguration(List<String> issuerCn, String url,
                                                                      String responderCertificateCn, boolean nonceDisabled) {
        IDCardConfigurationProvider.Ocsp ocsp = new IDCardConfigurationProvider.Ocsp();
        ocsp.setIssuerCn(issuerCn);
        ocsp.setUrl(url);
        ocsp.setNonceDisabled(nonceDisabled);
        ocsp.setAcceptedClockSkewInSeconds(2);
        ocsp.setResponseLifetimeInSeconds(900);
        ocsp.setResponderCertificateCn(responderCertificateCn);
        return ocsp;
    }


    public static X500PrivateCredential generateOcspResponderCertificate(String certDn, KeyPair certKeyPair, KeyPair caKeyPair, String issuerDn) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        X500Name issuerName = new X500Name(issuerDn);
        X500Name subjectName = new X500Name(certDn);
        BigInteger serial = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(Instant.now().minus(Duration.ofHours(1))), Date.from(Instant.now().plus(Duration.ofHours(1))), subjectName, certKeyPair.getPublic());
        builder.addExtension(Extension.extendedKeyUsage, true, new DERSequence(new ASN1Encodable[] {
                KeyPurposeId.id_kp_OCSPSigning.toOID()
        }));

        X509Certificate cert = signCertificate(builder, caKeyPair.getPrivate());

        return new X500PrivateCredential(cert, certKeyPair.getPrivate());
    }

    public static X500PrivateCredential generateUserCertificate(String certDn, KeyPair caKeyPair, String issuerDn) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        X500Name issuerName = new X500Name(issuerDn);
        X500Name subjectName = new X500Name(certDn);
        BigInteger serial = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair kp = rsa.generateKeyPair();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(Instant.now().minus(Duration.ofHours(1))), Date.from(Instant.now().plus(Duration.ofHours(1))), subjectName, kp.getPublic());

        AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://mock.ocsp.url")));
        ASN1EncodableVector aiaAsn = new ASN1EncodableVector();
        aiaAsn.add(caIssuers);
        builder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aiaAsn));

        X509Certificate cert = signCertificate(builder, caKeyPair.getPrivate());

        return new X500PrivateCredential(cert, kp.getPrivate());
    }

    public static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey caPrivateKey) throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caPrivateKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(signer));
    }

    private void assertMdcContent(String ocspUrl) {
        assertEquals(ocspUrl, MDC.get(Constants.MDC_ATTRIBUTE_OCSP_ID));
    }
}
