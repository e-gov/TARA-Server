package ee.ria.sso;


import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import org.bouncycastle.cert.ocsp.CertificateStatus;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;


/**
 * Created by serkp on 7.10.2017.
 */

@Component
@Qualifier(value = "ocspValidator")
public class OCSPValidator {

    private static final Logger log = LoggerFactory.getLogger(OCSPValidator.class);


    /**
     * @param userCert   - User certificate which will be checked from OCSP.
     * @param issuerCert - User certificate signer certificate (upper cert in chain).
     * @param ocspUrl    - OCSP url where request is sent
     * @return - TRUE if OCSP request was successful and certificate status was not UNKNOWN or
     * REVOKED. In other cases
     * will return FALSE and log errors.
     */
    public boolean isCertiticateValid(X509Certificate userCert, X509Certificate issuerCert,
                                      String ocspUrl) {
        log.info(
                "OCSP Certification validation called for userCert: {}, issuerCert: {}, certID: {}",
                userCert.getSubjectDN().getName(), issuerCert.getSubjectDN().getName(),
                userCert.getSerialNumber());

        try {
            CertificateID
                    certID =
                    generateCertifiacteIDForRequest(userCert.getSerialNumber(), issuerCert);

            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(certID);

            OCSPResp response = sendOCSPReq(builder.build(), ocspUrl);

            BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) response.getResponseObject();
            Optional<SingleResp> singleResponse = Arrays.stream(basicOCSPResponse.getResponses())
                                                        .filter(singleResp -> singleResp.getCertID()
                                                                                        .equals(certID))
                                                        .findFirst();

            if (!singleResponse.isPresent()) {
                log.error(
                        "OCSP response does't not contain correct single response for our request");
                return false;
            }


            CertificateStatus status = singleResponse.get().getCertStatus();

            if (isCertificateStatusGOOD(status)) {
                log.info("OCSP was successful and certificate is VALID");
                return true;
            }
        } catch (Exception e) {
            log.error("OCSP certification failed. Exception was thrown", e);
        }

        return false;
    }

    private boolean isCertificateStatusGOOD(CertificateStatus certificateStatus) {
        // this is actually null == null, because GOOD is null
        if (certificateStatus == CertificateStatus.GOOD) {
            return true;
        }

        if (certificateStatus instanceof RevokedStatus) {
            log.error("OCSP Status is revoked!");
            return false;
        } else if (certificateStatus instanceof UnknownStatus) {
            log.error("OCSP Status is unknown!");
            return false;
        } else {
            throw new IllegalStateException("Unknow ocsp response certification status OBJECT");
        }
    }


    /**
     * Sends OCSPReq to ocspUrl. Throws exception if HTTP response code not 2xx.
     */
    private OCSPResp sendOCSPReq(OCSPReq request, String ocspUrl) throws IOException {
        byte[] array = request.getEncoded();

        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.setDoOutput(true);

        log.info("Sending OCSP request to {}", ocspUrl);

        OutputStream out = con.getOutputStream();
        DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
        dataOut.write(array);
        dataOut.flush();
        dataOut.close();

        if (con.getResponseCode() / 100 != 2) {
            log.error("OCSP Request failed. HTTP {} - {}", con.getResponseCode(),
                      con.getResponseMessage());

        }

        //Get Response
        InputStream in = (InputStream) con.getContent();
        OCSPResp response = new OCSPResp(in);
        in.close();

        log.info("Read OCSP response.");

        return response;
    }

    private CertificateID generateCertifiacteIDForRequest(BigInteger userCertserialNumber,
                                                          X509Certificate issuerCert) throws
            OperatorCreationException,
            CertificateEncodingException, OCSPException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert), userCertserialNumber);

    }

}
