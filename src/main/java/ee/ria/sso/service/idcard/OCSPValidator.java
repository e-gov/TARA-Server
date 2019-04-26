package ee.ria.sso.service.idcard;

import ee.ria.sso.config.idcard.IDCardConfigurationProvider.Ocsp;
import ee.ria.sso.utils.X509Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.Conversion;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.MDC;
import org.springframework.util.Assert;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

import static ee.ria.sso.Constants.MDC_ATTRIBUTE_OCSP_ID;

@Slf4j
@RequiredArgsConstructor
public class OCSPValidator {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private final Map<String, X509Certificate> trustedCertificates;
    private final OCSPConfigurationResolver ocspConfigurationResolver;

    public void checkCert(X509Certificate userCert) {
        Assert.notNull(userCert, "User certificate cannot be null!");
        log.info("OCSP certificate validation. Serialnumber=<{}>, SubjectDN=<{}>, issuerDN=<{}>",
                userCert.getSerialNumber(), userCert.getSubjectDN().getName(), userCert.getIssuerDN().getName());
        List<Ocsp> ocspConfiguration = ocspConfigurationResolver.resolve(userCert);
        Assert.isTrue(CollectionUtils.isNotEmpty(ocspConfiguration), "At least one OCSP configuration must be present");

        int count = 0;
        int maxTries = ocspConfiguration.size();
        while (true) {
            Ocsp ocspConf = ocspConfiguration.get(count);
            try {
                if (count > 0) {
                    log.info("Retrying OCSP request with {}. Configuration: {}", ocspConf.getUrl(), ocspConf);
                }

                checkCert(userCert, ocspConf);
                return;
            } catch (OCSPServiceNotAvailableException e) {
                log.error("OCSP request has failed...");
                if (++count == maxTries) throw e;
            } catch (OCSPValidationException e) {
                throw e;
            }
        }
    }

    protected void checkCert(X509Certificate userCert, Ocsp ocspConf) {
        X509Certificate issuerCert = findIssuerCertificate(userCert);
        validateCertSignedBy(userCert, issuerCert);

        try {
            OCSPReq request = buildOCSPReq(userCert, issuerCert, ocspConf);
            OCSPResp response = sendOCSPReq(request, ocspConf);

            BasicOCSPResp ocspResponse = getResponse(response, ocspConf);
            validateResponseNonce(request, ocspResponse, ocspConf);
            validateResponseSignature(ocspResponse, issuerCert, ocspConf);

            SingleResp singleResponse = getSingleResp(ocspResponse, request.getRequestList()[0].getCertID());
            validateResponseThisUpdate(singleResponse, ocspConf.getAcceptedClockSkewInSeconds(), ocspConf.getResponseLifetimeInSeconds());
            validateCertStatus(singleResponse);
        } catch (OCSPValidationException | OCSPServiceNotAvailableException e) {
            throw e;
        } catch (SocketTimeoutException | SocketException | UnknownHostException e) {
            throw new OCSPServiceNotAvailableException("OCSP not available: " + ocspConf.getUrl(), e);
        } catch (Exception e) {
            throw new IllegalStateException("OCSP validation failed: " + e.getMessage(), e);
        }
    }

    private BasicOCSPResp getResponse(OCSPResp response, Ocsp ocspConf)
            throws IOException, OCSPException {
        log.info("OCSP response received: {}", Base64.getEncoder().encodeToString(response.getEncoded()));
        BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) response.getResponseObject();
        Assert.notNull(basicOCSPResponse, "Invalid OCSP response! OCSP response object bytes could not be read!");
        Assert.notNull(basicOCSPResponse.getCerts(), "Invalid OCSP response! OCSP response is missing mandatory element - the signing certificate");
        Assert.isTrue(basicOCSPResponse.getCerts().length >= 1, "Invalid OCSP response! Expecting at least one OCSP responder certificate");
        MDC.put(MDC_ATTRIBUTE_OCSP_ID, ocspConf.getUrl());
        return basicOCSPResponse;
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

    private OCSPReq buildOCSPReq(X509Certificate userCert, X509Certificate issuerCert, Ocsp conf)
            throws OCSPException, IOException, CertificateEncodingException, OperatorCreationException {
        OCSPReqBuilder builder = new OCSPReqBuilder();

        CertificateID certificateID = generateCertificateIdForRequest(userCert, issuerCert);
        builder.addRequest(certificateID);

        if (!conf.isNonceDisabled()) {
            DEROctetString nonce = generateDerOctetStringForNonce(UUID.randomUUID());
            Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
            builder.setRequestExtensions(new Extensions(new Extension[]{extension}));
        }

        return builder.build();
    }

    private OCSPResp sendOCSPReq(OCSPReq request, Ocsp conf) throws IOException {
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

        if (connection.getResponseCode() == 200) {
            String contentType = connection.getHeaderField("Content-Type");
            if (StringUtils.isEmpty(contentType) || !contentType.equals("application/ocsp-response")) {
                throw new OCSPServiceNotAvailableException("Response Content-Type header is missing or invalid. " +
                        "Expected: 'application/ocsp-response', actual: " + contentType);
            }

            try (InputStream in = (InputStream) connection.getContent()) {
                return new OCSPResp(in);
            }
        } else {
            this.log.error("OCSP request has failed (HTTP {}) - {}",
                    connection.getResponseCode(), connection.getResponseMessage());
            throw new OCSPServiceNotAvailableException(String.format("Service returned HTTP status code %d",
                    connection.getResponseCode()));
        }
    }

    private SingleResp getSingleResp(BasicOCSPResp basicOCSPResponse, CertificateID certificateID) {
        Optional<SingleResp> singleResponse = Arrays.stream(basicOCSPResponse.getResponses())
                .filter(singleResp -> singleResp.getCertID().equals(certificateID))
                .findFirst();
        Assert.isTrue(singleResponse.isPresent(), "No OCSP response is present");
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

    private void validateResponseNonce(OCSPReq request, BasicOCSPResp response, Ocsp ocspConf) {
        if (!ocspConf.isNonceDisabled()) {
            Extension requestExtension = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            DEROctetString nonce = (DEROctetString)requestExtension.getExtnValue();

            Extension responseExtension = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (responseExtension == null)
                throw new IllegalStateException("No nonce found in OCSP response");

            DEROctetString receivedNonce = (DEROctetString) responseExtension.getExtnValue();
            if (!nonce.equals(receivedNonce))
                throw new IllegalStateException("Invalid OCSP response nonce");
        }
    }

    private void validateResponseThisUpdate(SingleResp response, long acceptedClockSkew, long responseLifetime) {
        final Instant thisUpdate = response.getThisUpdate().toInstant();
        final Instant now = Instant.now();

        if (thisUpdate.isBefore(now.minusSeconds(acceptedClockSkew + responseLifetime)))
            throw new IllegalStateException("OCSP response was older than accepted");
        if (thisUpdate.isAfter(now.plusSeconds(acceptedClockSkew)))
            throw new IllegalStateException("OCSP response cannot be produced in the future");
    }

    private void validateResponseSignature(BasicOCSPResp response, X509Certificate userCertIssuer, Ocsp ocspConfiguration)
            throws OCSPException, OperatorCreationException, CertificateException, IOException {

        X509Certificate signingCert = getResponseSigningCert(response, userCertIssuer, ocspConfiguration);
        Assert.isTrue(signingCert.getExtendedKeyUsage() != null
                        && signingCert.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_OCSPSigning.getId()),
                "This certificate has no OCSP signing extension (subjectDn='" + signingCert.getSubjectDN() + "')");
        verifyResponseSignature(response, signingCert);
    }

    private X509Certificate getResponseSigningCert(BasicOCSPResp response, X509Certificate userCertIssuer, Ocsp ocspConfiguration)
            throws CertificateException, IOException {
        String responderCn = getResponderCN(response);

        // if explicit responder cert is set in configuration, then response signature MUST be verified with it
        if (ocspConfiguration.getResponderCertificateCn() != null) {
            X509Certificate signCert = trustedCertificates.get(ocspConfiguration.getResponderCertificateCn());
            Assert.notNull(signCert, "Certificate with CN: '" + ocspConfiguration.getResponderCertificateCn()
                    + "' is not trusted! Please check your configuration!");
            Assert.isTrue(responderCn.equals(ocspConfiguration.getResponderCertificateCn()),
                    "OCSP provider has signed the response using cert with CN: '" + responderCn
                            + "', but configuration expects response to be signed with a different certificate (CN: '"
                            + ocspConfiguration.getResponderCertificateCn() + "')!");
            return signCert;
        } else {
            // othwerwise the response must be signed with one of the trusted ocsp responder certs OR it's signer cert must be issued by the same CA as user cert
            X509Certificate signCert = trustedCertificates.get(responderCn);
            if (signCert == null) {
                signCert = getCertFromOcspResponse(response, responderCn);
                X509Certificate responderCertIssuerCert = findIssuerCertificate(signCert);
                if (responderCertIssuerCert.equals(userCertIssuer)) {
                    return signCert;
                } else {
                    throw new IllegalStateException("In case of AIA OCSP, the OCSP responder certificate must be issued " +
                            "by the authority that issued the user certificate. Expected issuer: '" + userCertIssuer.getSubjectX500Principal() + "', " +
                            "but the OCSP responder signing certificate was issued by '" + responderCertIssuerCert.getSubjectX500Principal() + "'");
                }
            } else {
                return signCert;
            }
        }
    }

    private X509Certificate getCertFromOcspResponse(BasicOCSPResp response, String cn) throws CertificateException, IOException {
        Optional<X509CertificateHolder> cert = Arrays.stream(response.getCerts()).filter(c -> X509Utils.getFirstCNFromX500Name(c.getSubject()).equals(cn)).findFirst();
        Assert.isTrue(cert.isPresent(), "Invalid OCSP response! Responder ID in response contains value: " + cn
                + ", but there was no cert provided with this CN in the response.");
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(cert.get().getEncoded())
        );
    }

    private void verifyResponseSignature(BasicOCSPResp response, X509Certificate responseSignCertificate) throws CertificateExpiredException, CertificateNotYetValidException, OperatorCreationException, OCSPException {
        responseSignCertificate.checkValidity();

        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(responseSignCertificate.getPublicKey());

        if (!response.isSignatureValid(verifierProvider))
            throw new IllegalStateException("OCSP response signature is not valid");
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

    private void validateCertSignedBy(X509Certificate cert, X509Certificate signedBy) {
        try {
            cert.verify(signedBy.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            throw new IllegalStateException("Failed to verify user certificate", e);
        }
    }
}
