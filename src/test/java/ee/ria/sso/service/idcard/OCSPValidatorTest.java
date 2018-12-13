package ee.ria.sso.service.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import ee.ria.sso.service.idcard.OCSPValidationException;
import ee.ria.sso.service.idcard.OCSPValidator;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.function.Function;
import java.util.function.Supplier;

@RunWith(SpringJUnit4ClassRunner.class)
public class OCSPValidatorTest {

    private static final OcspResponseTransformer ocspResponseTransformer = new OcspResponseTransformer();
    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().dynamicPort().extensions(ocspResponseTransformer)
    );

    private static final String MOCK_ISSUER_CERT_PATH = "classpath:ocsp/TEST_of_ESTEID-SK_2015.crt";
    private static final String MOCK_USER_CERT_PATH = "classpath:id-card/47101010033(TEST_of_ESTEID-SK_2015).pem";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private ResourceLoader resourceLoader;

    @InjectMocks
    private OCSPValidator ocspValidator;
    private OCSPValidator.OCSPConfiguration ocspConfiguration;
    private KeyPair responderKeys;

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
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);

        ocspConfiguration = new OCSPValidator.OCSPConfiguration(
                String.format("http://localhost:%d/ocsp", wireMockServer.port()),
                Collections.emptyMap(), 2, 900
        );
    }

    @Test
    public void validateShouldThrowExceptionWhenUserCertIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("User certificate cannot be null!");
        ocspValidator.validate(null, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenIssuerCertIsMissing() throws Exception {
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Issuer certificate cannot be null!");
        ocspValidator.validate(userCert, null, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspConfigurationIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("OCSP configuration cannot be null!");
        ocspValidator.validate(userCert, issuerCert, null);
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

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseValidationCertMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP cert not found from setup");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseNonceIsMissing() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);
        ocspResponseTransformer.setNonceResolver(nonce -> null);

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("No nonce found in OCSP response");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseNonceIsInvalid() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);
        ocspResponseTransformer.setNonceResolver(nonce -> {
            return new DEROctetString(new byte[]{ 0 });
        });

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid OCSP response nonce");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseThisUpdateIsTooOld() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);
        ocspResponseTransformer.setThisUpdateProvider(() -> {
            final Instant instant = Instant.now()
                    .minusSeconds(ocspConfiguration.getAcceptedClockSkew())
                    .minusSeconds(ocspConfiguration.getResponseLifetime())
                    .minusSeconds(1L);
            return Date.from(instant);
        });

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP response was older than accepted");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseThisUpdateIsInTheFuture() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);
        ocspResponseTransformer.setThisUpdateProvider(() -> {
            final Instant instant = Instant.now()
                    .plusSeconds(ocspConfiguration.getAcceptedClockSkew())
                    .plusSeconds(1L);
            return Date.from(instant);
        });

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP response cannot be produced in the future");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenOcspResponseSignatureIsInvalid() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);

        updateOcspConfigurationWithGeneratedCertificate(
                KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair()
        );

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("OCSP response signature is not valid");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenCertificateStatusIsRevoked() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, new RevokedStatus(
                new Date(), CRLReason.unspecified
        ));

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid certificate status <REVOKED> received");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldThrowExceptionWhenCertificateStatusIsUnknown() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, new UnknownStatus());
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);

        expectedEx.expect(OCSPValidationException.class);
        expectedEx.expectMessage("Invalid certificate status <UNKNOWN> received");

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
    }

    @Test
    public void validateShouldSucceed() throws Exception {
        X509Certificate issuerCert = loadCertificateFromResource(MOCK_ISSUER_CERT_PATH);
        X509Certificate userCert = loadCertificateFromResource(MOCK_USER_CERT_PATH);
        updateWiremockOcspResponse(OCSPResp.SUCCESSFUL, org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
        updateOcspConfigurationWithGeneratedCertificate(responderKeys);

        ocspValidator.validate(userCert, issuerCert, ocspConfiguration);
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

    private void updateOcspConfigurationWithGeneratedCertificate(KeyPair keyPair) throws CertificateException, CertIOException, OperatorCreationException {
        ocspConfiguration.setTrustedCertificates(Collections.singletonMap(
                "TEST of SK OCSP RESPONDER 2011", generateCertificate(keyPair)
        ));
    }

    private static void updateWiremockOcspResponse(int responseStatus, org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus) {
        ocspResponseTransformer.setResponseStatus(responseStatus);
        ocspResponseTransformer.setCertificateStatus(certificateStatus);

        wireMockServer.stubFor(WireMock.post("/ocsp")
                .willReturn(WireMock.aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/ocsp-request")
                )
        );
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

        @Override
        public Response transform(Request request, Response response, FileSource fileSource, Parameters parameters) {
            if (response.getStatus() != 200) return response;
            byte[] responseBytes;

            try {
                OCSPReq ocspReq = new OCSPReq(request.getBody());
                Assert.assertNotNull(ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
                Assert.assertEquals(1, ocspReq.getRequestList().length);

                DEROctetString nonce = (DEROctetString) ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue();
                validateNonceDerOctetString(nonce);

                BasicOCSPResp basicOCSPResp = mockOcspResponse(ocspReq.getRequestList()[0].getCertID(), this.nonceResolver.apply(nonce));
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

        private BasicOCSPResp mockOcspResponse(CertificateID certificateID, DEROctetString nonce) throws OCSPException, OperatorCreationException {
            RespID respID = new RespID(new X500Name("C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee"));
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
                    new JcaContentSignerBuilder("SHA256withRSA").build(this.signerKey),
                    null,
                    Date.from(Instant.now())
            );
        }

    }

}
