package ee.ria.sso.validators;


import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;


/**
 * Created by serkp on 7.10.2017.
 */

@Component
public class OCSPValidator {

    private final Logger log = LoggerFactory.getLogger(OCSPValidator.class);

    public void validate(X509Certificate userCert, X509Certificate issuerCert, String url) {
        this.log.debug("OCSP certificate validation called for userCert: {}, issuerCert: {}, certID: {}",
            userCert.getSubjectDN().getName(), issuerCert.getSubjectDN().getName(), userCert.getSerialNumber());
        try {
            CertificateID certID = this.generateCertificateIdForRequest(userCert.getSerialNumber(), issuerCert);
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(certID);
            OCSPResp response = this.sendOCSPReq(builder.build(), url);
            BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) response.getResponseObject();
            Optional<SingleResp> singleResponse = Arrays.stream(basicOCSPResponse.getResponses())
                .filter(singleResp -> singleResp.getCertID().equals(certID)).findFirst();
            if (!singleResponse.isPresent()) {
                throw new RuntimeException("No OCSP response is present");
            }
            org.bouncycastle.cert.ocsp.CertificateStatus status = singleResponse.get().getCertStatus();
            if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                return;
            }
            if (status instanceof RevokedStatus) {
                throw OCSPValidationException.of(CertificateStatus.REVOKED);
            } else if (status instanceof UnknownStatus) {
                throw OCSPValidationException.of(CertificateStatus.UNKNOWN);
            } else {
                throw new IllegalStateException(String.format("Unknown OCSP certificate status <%s> received", status));
            }
        } catch (OCSPValidationException e) {
            throw e;
        } catch (Exception e) {
            throw OCSPValidationException.of(e);
        }
    }

    /*
     * RESTRICTED METHODS
     */

    private OCSPResp sendOCSPReq(OCSPReq request, String url) throws IOException {
        byte[] bytes = request.getEncoded();
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setDoOutput(true);
        this.log.debug("Sending OCSP request to <{}>", url);
        DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(connection.getOutputStream()));
        outputStream.write(bytes);
        outputStream.flush();
        outputStream.close();
        if (connection.getResponseCode() != 200) {
            this.log.error("OCSP request has been failed (HTTP {}) - {}", connection.getResponseCode(),
                connection.getResponseMessage());
        }
        try (InputStream in = (InputStream) connection.getContent()) {
            return new OCSPResp(in);
        }
    }

    private CertificateID generateCertificateIdForRequest(BigInteger userCertSerialNumber, X509Certificate issuerCert)
        throws OperatorCreationException, CertificateEncodingException, OCSPException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new CertificateID(
            new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
            new JcaX509CertificateHolder(issuerCert), userCertSerialNumber);
    }

}
