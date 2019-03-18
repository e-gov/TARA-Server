package ee.ria.sso.utils;


import lombok.extern.slf4j.Slf4j;
import org.apache.axis.encoding.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by serkp on 7.10.2017.
 */

@Slf4j
public class X509Utils {

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

    public static String getOCSPUrl(X509Certificate certificate) {
        ASN1Primitive obj;
        try {
            obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
        } catch (IOException ex) {
            log.error("Failed to get OCSP URL", ex);
            return null;
        }

        if (obj == null) {
            return null;
        }

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)
                    && accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {

                DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) accessDescription.getAccessLocation().toASN1Primitive(), false);
                return derStr.getString();
            }
        }

        return null;
    }

    private static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }
}
