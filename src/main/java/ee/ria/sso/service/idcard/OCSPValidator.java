package ee.ria.sso.service.idcard;

import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.utils.X509Utils;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.Conversion;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import java.io.*;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

@RequiredArgsConstructor
public class OCSPValidator {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private final Logger log = LoggerFactory.getLogger(OCSPValidator.class);
    private final Map<String, X509Certificate> trustedCertificates;
    private final OCSPConfigurationResolver ocspConfigurationResolver;


    public void checkCert(X509Certificate userCert) {
        Assert.notNull(userCert, "User certificate cannot be null!");
        List<IDCardConfigurationProvider.Ocsp> ocspConfiguration = ocspConfigurationResolver.resolve(userCert);
        Assert.isTrue(CollectionUtils.isNotEmpty(ocspConfiguration), "At least one OCSP configuration must be present");

        int count = 0;
        int maxTries = ocspConfiguration.size();
        while (true) {
            try {
                if (count > 0) {
                    log.info("Retrying OCSP request with {}. Configuration details: {}", ocspConfiguration.get(count).getUrl(), ocspConfiguration.get(count));
                }

                validate(userCert, ocspConfiguration.get(count));
                return;
            } catch (OCSPConnectionFailedException e) {
                log.error("OCSP request timed out...");
                if (++count == maxTries) throw e;
            } catch (OCSPValidationException e) {
                throw e;
            }
        }
    }

    protected void validate(X509Certificate userCert, IDCardConfigurationProvider.Ocsp ocspConf) {
        X509Certificate issuerCert = findIssuerCertificate(userCert);
        log.debug("OCSP certificate validation called for userCert: {}, issuerCert: {}, certID: {}",
                userCert.getSubjectDN().getName(), issuerCert.getSubjectDN().getName(), userCert.getSerialNumber());

        validateCertIssuerBy(userCert, issuerCert);

        try {
            CertificateID certificateID = generateCertificateIdForRequest(userCert, issuerCert);
            DEROctetString nonce = generateDerOctetStringForNonce(UUID.randomUUID());
            OCSPReq request = buildOCSPReq(certificateID, nonce, ocspConf);
            OCSPResp response = sendOCSPReq(request, ocspConf);
            validateResponse(ocspConf, issuerCert, certificateID, nonce, response);
        } catch (OCSPValidationException e) {
            throw e;
        } catch (SocketTimeoutException | ConnectException e) {
            throw new OCSPConnectionFailedException(e);
        } catch (Exception e) {
            throw new IllegalStateException("OCSP validation failed: " + e.getMessage(), e);
        }
    }


    private void validateResponse(IDCardConfigurationProvider.Ocsp ocspConf, X509Certificate issuerCert, CertificateID certificateID, DEROctetString nonce, OCSPResp response) throws IOException, OCSPException, OperatorCreationException, CertificateException {
        log.info("OCSP response received: {}", Base64.getEncoder().encodeToString(response.getEncoded()));
        BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) response.getResponseObject();
        Assert.notNull(basicOCSPResponse, "Invalid OCSP response! OCSP response object bytes could not be read!");

        if (!ocspConf.isNonceDisabled()) {
            validateResponseNonce(basicOCSPResponse, nonce);
        }

        validateResponseSignature(basicOCSPResponse, trustedCertificates, ocspConf, issuerCert);

        SingleResp singleResponse = getSingleResp(basicOCSPResponse, certificateID);
        validateResponseThisUpdate(singleResponse, ocspConf.getAcceptedClockSkewInSeconds(), ocspConf.getResponseLifetimeInSeconds());
        validateCertStatus(singleResponse);
    }

    private void validateCertStatus(SingleResp singleResponse) {
        org.bouncycastle.cert.ocsp.CertificateStatus status = singleResponse.getCertStatus();

        if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
            return;
        } else if (status instanceof RevokedStatus) {
            throw OCSPValidationException.of(CertificateStatus.REVOKED);
        } else {
            throw OCSPValidationException.of(CertificateStatus.UNKNOWN);
        }
    }

    private OCSPReq buildOCSPReq(CertificateID certificateID, DEROctetString nonce, IDCardConfigurationProvider.Ocsp conf) throws OCSPException {
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certificateID);

        if (!conf.isNonceDisabled()) {
            Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
            builder.setRequestExtensions(new Extensions(new Extension[]{extension}));
        }

        return builder.build();
    }

    private OCSPResp sendOCSPReq(OCSPReq request, IDCardConfigurationProvider.Ocsp conf) throws IOException {
        byte[] bytes = request.getEncoded();

        HttpURLConnection connection = (HttpURLConnection) new URL(conf.getUrl()).openConnection();
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setConnectTimeout(conf.getConnectTimeoutInMilliseconds());
        connection.setReadTimeout(conf.getReadTimeoutInMilliseconds());
        connection.setDoOutput(true);

        this.log.info("Sending OCSP request to <{}>. Request payload: <{}>. OCSP configuration: <{}>", conf.getUrl(), Base64.getEncoder().encodeToString(bytes), conf);
        try (DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(connection.getOutputStream()))) {
            outputStream.write(bytes);
            outputStream.flush();
        }

        if (connection.getResponseCode() != 200) {
            this.log.error("OCSP request has been failed (HTTP {}) - {}",
                    connection.getResponseCode(), connection.getResponseMessage());
            throw new IllegalStateException(String.format("OCSP request failed with status code %d",
                    connection.getResponseCode()));
        }

        try (InputStream in = (InputStream) connection.getContent()) {
            return new OCSPResp(in);
        }
    }

    private SingleResp getSingleResp(BasicOCSPResp basicOCSPResponse, CertificateID certificateID) {
        Optional<SingleResp> singleResponse = Arrays.stream(basicOCSPResponse.getResponses())
                .filter(singleResp -> singleResp.getCertID().equals(certificateID))
                .findFirst();

        if (!singleResponse.isPresent())
            throw new IllegalStateException("No OCSP response is present");

        return singleResponse.get();
    }

    private CertificateID generateCertificateIdForRequest(X509Certificate userCert, X509Certificate issuerCert)
            throws OperatorCreationException, CertificateEncodingException, OCSPException {
        BigInteger userCertSerialNumber = userCert.getSerialNumber();
        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert),
                userCertSerialNumber
        );
    }

    private DEROctetString generateDerOctetStringForNonce(UUID uuid) throws IOException {
        byte[] uuidBytes = Conversion.uuidToByteArray(uuid, new byte[16], 0, 16);
        return new DEROctetString(new DEROctetString(uuidBytes));
    }

    private void validateResponseNonce(BasicOCSPResp response, DEROctetString nonce) {
        Extension extension = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (extension == null)
            throw new IllegalStateException("No nonce found in OCSP response");

        DEROctetString receivedNonce = (DEROctetString) extension.getExtnValue();
        if (!nonce.equals(receivedNonce))
            throw new IllegalStateException("Invalid OCSP response nonce");
    }

    private void validateResponseThisUpdate(SingleResp response, long acceptedClockSkew, long responseLifetime) {
        final Instant thisUpdate = response.getThisUpdate().toInstant();
        final Instant now = Instant.now();

        if (thisUpdate.isBefore(now.minusSeconds(acceptedClockSkew + responseLifetime)))
            throw new IllegalStateException("OCSP response was older than accepted");
        if (thisUpdate.isAfter(now.plusSeconds(acceptedClockSkew)))
            throw new IllegalStateException("OCSP response cannot be produced in the future");
    }

    private void validateResponseSignature(BasicOCSPResp response, Map<String, X509Certificate> trustedCertificates, IDCardConfigurationProvider.Ocsp ocspConfiguration, X509Certificate userCertIssuer)
            throws OCSPException, OperatorCreationException, CertificateException, IOException {

        String responderId = getResponderCN(response);
        log.debug("Responder cert CN: {}", responderId);

        X509Certificate responseSignCertificate;

        if (ocspConfiguration.getResponderCertificateCn() == null) {
            responseSignCertificate = getOcspResponderCertFromResponse(response, responderId);

            verifyOcspResponderCertIssuer(userCertIssuer, responseSignCertificate);
        } else {
            responseSignCertificate = getOcspResponderCertFromTruststore(trustedCertificates,
                    ocspConfiguration, responderId);
        }

        verifyResponseSignature(response, responseSignCertificate);
    }

    protected void verifyOcspResponderCertIssuer(X509Certificate userCertIssuer, X509Certificate responseSignCertificate) {
        X509Certificate responderCertIssuerCert = findIssuerCertificate(responseSignCertificate);
        if (!responderCertIssuerCert.equals(userCertIssuer)) {
            throw new IllegalStateException("In case of AIA OCSP, the OCSP responder certificate must be issued " +
                    "by the authority that issued the user certificate. Expected issuer: '" + userCertIssuer.getSubjectX500Principal() + "', " +
                    "but the OCSP responder signing certificate was issued by '" + responderCertIssuerCert.getSubjectX500Principal() + "'");
        }
    }

    private X509Certificate getOcspResponderCertFromResponse(BasicOCSPResp response, String responderCertCnInResponse) throws CertificateException, IOException {
        X509Certificate responseSignCertificate;
        log.debug("Expecting the OCSP response to be signed by a temporary intermediate certificate (issued by the same authority that issued the user cert)");

        Assert.notNull(response.getCerts(), "Invalid OCSP response! OCSP response is missing mandatory element - the signing certificate");
        Assert.isTrue(response.getCerts().length >= 1, "Expecting at least one OCSP responder certificate");

        X509CertificateHolder responderCertificate = getLeafCertFromChainByCn(response.getCerts(), responderCertCnInResponse);
        Assert.notNull(responderCertificate, "Invalid OCSP response! Responder ID in response contains value: " + responderCertCnInResponse + ", but there was no cert provided with this CN in the response.");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        responseSignCertificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(responderCertificate.getEncoded())
        );
        return responseSignCertificate;
    }

    private X509Certificate getOcspResponderCertFromTruststore(Map<String, X509Certificate> trustedCertificates, IDCardConfigurationProvider.Ocsp ocsp, String responderCertCnInResponse) {
        X509Certificate responseSignCertificate;
        Assert.isTrue(responderCertCnInResponse.equals(ocsp.getResponderCertificateCn()),
                "OCSP provider has signed the response using cert with CN: '" + responderCertCnInResponse
                        + "', but configuration expects response to be signed with a different certificate (CN: '"
                        + ocsp.getResponderCertificateCn() + "')!");

        responseSignCertificate = trustedCertificates.get(responderCertCnInResponse);

        if (responseSignCertificate == null) {
            throw new IllegalStateException("OCSP certificate with CN: '" + responderCertCnInResponse + "' was not found! Please check your configuration!");
        }
        return responseSignCertificate;
    }

    private void verifyResponseSignature(BasicOCSPResp response, X509Certificate responseSignCertificate) throws CertificateExpiredException, CertificateNotYetValidException, OperatorCreationException, OCSPException {
        responseSignCertificate.checkValidity();

        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(responseSignCertificate.getPublicKey());

        if (!response.isSignatureValid(verifierProvider))
            throw new IllegalStateException("OCSP response signature is not valid");
    }

    private X509CertificateHolder getLeafCertFromChainByCn(X509CertificateHolder[] certs, String responderCertCnInResponse) {
        for (X509CertificateHolder cert : certs) {
            String cn = X509Utils.getFirstCNFromX500Name(cert.getSubject());
            log.debug("Cert in OCSP response: '{}'", cn);
            if (cn.equals(responderCertCnInResponse))
                return cert;
        }

        return null;
    }

    private X509Certificate findIssuerCertificate(X509Certificate certificate) {
        String issuerCN = X509Utils.getIssuerCNFromCertificate(certificate);
        log.debug("IssuerCN extracted: {}", issuerCN);
        X509Certificate issuerCert = trustedCertificates.get(issuerCN);
        Assert.notNull(issuerCert, "Issuer certificate with CN '" + issuerCN + "' is not a trusted certificate!");
        return issuerCert;
    }

    private String getResponderCN(BasicOCSPResp response) {
        try {
            return X509Utils.getFirstCNFromX500Name(
                    response.getResponderId().toASN1Primitive().getName()
            );
        } catch (Exception e) {
            throw new IllegalStateException("Unable to find responder CN from OCSP response", e);
        }
    }

    private void validateCertIssuerBy(X509Certificate userCert, X509Certificate issuerCert) {
        try {
            userCert.verify(issuerCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            throw new IllegalStateException("Failed to verify user certificate", e);
        }
    }
}
