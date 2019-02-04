package ee.ria.sso.utils;


import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.Collection;
import java.util.List;

import org.apache.axis.encoding.Base64;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by serkp on 7.10.2017.
 */

public class X509Utils {

    private static final Logger log = LoggerFactory.getLogger(X509Utils.class);
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    public static X509Certificate toX509Certificate(String encodedCertificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(encodedCertificate
                    .replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""))));
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to decode certificate", e);
        }
    }

    public static String getIssuerCNFromCertificate(X509Certificate certificate) {
        try {
            return getFirstCNFromX500Name(
                    new JcaX509CertificateHolder(certificate).getIssuer()
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Unable to get issuer CN from certificate", e);
        }
    }

    public static String getSubjectCNFromCertificate(X509Certificate certificate) {
        try {
            return getFirstCNFromX500Name(
                    new JcaX509CertificateHolder(certificate).getSubject()
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Unable to get subject CN from certificate", e);
        }
    }

    public static String getFirstCNFromX500Name(X500Name x500Name) {
        final RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public static String getRfc822NameSubjectAltName(X509Certificate certificate) {
        try {
            Collection<List<?>> sanFields = certificate.getSubjectAlternativeNames();

            if (sanFields == null)
                throw new IllegalArgumentException("This certificate does not contain any Subject Alternative Name fields!");

            return certificate.getSubjectAlternativeNames()
                    .stream()
                    .filter(e -> e.get(0).equals(GeneralName.rfc822Name))
                    .findFirst()
                    .map(e -> e.get(1).toString())
                    .orElseGet(null);
        } catch (CertificateParsingException e) {
            return null;
        }
    }

}
