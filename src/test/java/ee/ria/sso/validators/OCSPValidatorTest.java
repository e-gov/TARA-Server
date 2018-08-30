package ee.ria.sso.validators;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.CertIOException;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.function.Function;

@RunWith(SpringJUnit4ClassRunner.class)
public class OCSPValidatorTest {

    private static final OcspResponseTransformer ocspResponseTransformer = new OcspResponseTransformer();
    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().dynamicPort().extensions(ocspResponseTransformer)
    );

    private static final String MOCK_RESPONDER_CERT_PATH = "classpath:ocsp/TEST_of_SK_OCSP_RESPONDER_2011.crt";
    private static final String MOCK_ISSUER_CERT_PATH = "classpath:ocsp/TEST_of_ESTEID-SK_2011.crt";
    private static final String MOCK_USER_CERT_PATH = "classpath:id-card/47101010033.pem";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private ResourceLoader resourceLoader;

    @InjectMocks
    private OCSPValidator ocspValidator;
    private KeyPair responderKeys;
    private String mockOcspUrl;

    @BeforeClass
    public static void setUp() {
        wireMockServer.start();
    }

    @AfterClass
    public static void tearDown() {
        wireMockServer.stop();
    }

    @Before
    public void setUpTest() throws Exception {
        ocspValidator = new OCSPValidator();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        mockOcspUrl = String.format("http://localhost:%d/ocsp", wireMockServer.port());
    }

    @Test
    public void validateShouldThrowExceptionWhenUserCertIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("User certificate cannot be null!");
        ocspValidator.validate(null, issuerCert, mockOcspUrl, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenIssuerCertIsMissing() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Issuer certificate cannot be null!");
        ocspValidator.validate(userCert, null, mockOcspUrl, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspUrlIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("OCSP URL cannot be null!");
        ocspValidator.validate(userCert, issuerCert, null, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenCertificateMapIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Map of trusted certificates cannot be null!");
        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, null);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspRespondsNotOk() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        wireMockServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(500))
        );

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP request failed with status code 500");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseValidationCertMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, CertificateStatus.GOOD);

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP cert not found from setup");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.emptyMap());
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseNonceIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, CertificateStatus.GOOD);
        ocspResponseTransformer.setNonceResolver(nonce -> null);

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("No nonce found in OCSP response");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(responderKeys)
        ));
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseNonceIsInvalid() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, CertificateStatus.GOOD);
        ocspResponseTransformer.setNonceResolver(nonce -> {
            return new DEROctetString(new byte[]{ 0 });
        });

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid OCSP response nonce");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(responderKeys)
        ));
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseSignatureIsInvalid() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, CertificateStatus.GOOD);

        KeyPair nonResponderKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP response signature is not valid");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(nonResponderKeyPair)
        ));
    }

    @Test
    public void validateShouldThrowExceptionWhenCertificateStatusIsRevoked() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, new RevokedStatus(
                new Date(), CRLReason.unspecified
        ));

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid certificate status <REVOKED> received");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(responderKeys)
        ));
    }

    @Test
    public void validateShouldThrowExceptionWhenCertificateStatusIsUnknown() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, new UnknownStatus());

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid certificate status <UNKNOWN> received");

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(responderKeys)
        ));
    }

    @Test
    public void validateShouldSucceed() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, CertificateStatus.GOOD);

        ocspValidator.validate(userCert, issuerCert, mockOcspUrl, Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(responderKeys)
        ));
    }

    private X509Certificate generateCertificate(KeyPair keyPair) throws OperatorCreationException, CertIOException, CertificateException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee");
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

    private static BasicOCSPResp mockOcspResponse(CertificateID certificateID, CertificateStatus certificateStatus, DEROctetString nonce, PrivateKey signerKey)
            throws OCSPException, OperatorCreationException {
        RespID respID = new RespID(new X500Name("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee"));
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respID);
        builder.addResponse(certificateID, certificateStatus);

        if (nonce != null) {
            Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
            builder.setResponseExtensions(new Extensions(new Extension[]{ extension }));
        }

        return builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(signerKey),
                null,
                Date.from(Instant.now())
        );
    }

    private static void updateWiremockOcspResponse(int responseStatus, CertificateStatus certificateStatus) throws IOException {
        ocspResponseTransformer.setResponseStatus(responseStatus);
        ocspResponseTransformer.setCertificateStatus(certificateStatus);
        ocspResponseTransformer.setNonceResolver(null);

        wireMockServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/ocsp-request")
                )
        );
    }

    @Setter
    public static class OcspResponseTransformer extends ResponseTransformer {

        private int responseStatus;
        private CertificateStatus certificateStatus;
        private Function<DEROctetString, DEROctetString> nonceResolver;
        private PrivateKey signerKey;

        @Override
        public Response transform(Request request, Response response, FileSource fileSource, Parameters parameters) {
            if (response.getStatus() != 200) return response;
            byte[] responseBytes;

            try {
                OCSPReq ocspReq = new OCSPReq(request.getBody());
                Assert.assertNotNull(ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
                Assert.assertEquals(1, ocspReq.getRequestList().length);

                DEROctetString nonce = (DEROctetString) ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue();
                if (this.nonceResolver != null) nonce = this.nonceResolver.apply(nonce);

                BasicOCSPResp basicOCSPResp = mockOcspResponse(
                        ocspReq.getRequestList()[0].getCertID(),
                        this.certificateStatus,
                        nonce,
                        this.signerKey
                );

                OCSPResp ocspResp = new OCSPRespBuilder()
                        .build(this.responseStatus, basicOCSPResp);

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
    }

}
