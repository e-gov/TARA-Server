package ee.ria.sso.utils;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
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

@RunWith(SpringJUnit4ClassRunner.class)
public class X509UtilsTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private ResourceLoader resourceLoader;

    String certWithNoSanFields = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEhjCCA26gAwIBAgIQA24ff8C5+JBPQMKCfhmYKDANBgkqhkiG9w0BAQUFADAh\n" +
            "MQ8wDQYDVQQLDAZTYW1wbGUxDjAMBgNVBAMMBU15IENBMB4XDTEyMDIxOTA5MzYw\n" +
            "MVoXDTEzMDEzMDIxNTk1OVowga4xCzAJBgNVBAYTAkVFMRQwEgYDVQQKDAtFSUQg\n" +
            "KFNFV0VEKTEXMBUGA1UECwwOYXV0aGVudGljYXRpb24xLTArBgNVBAMMJFBFUkU5\n" +
            "NTc5Njk1MSxFRVM5NTc5MTgxMyw0OTYwMzI4ODk3NzEVMBMGA1UEBAwMUEVSRTk1\n" +
            "Nzk2OTUxMRQwEgYDVQQqDAtFRVM5NTc5MTgxMzEUMBIGA1UEBRMLNDk2MDMyODg5\n" +
            "NzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAIQEcG27FJucfWPCfCZj\n" +
            "AVZiVzKlptZFuKmuF9BmBI1dQkOmK5GHLmEYthayc8wNK2lF1f3auvGR7PaQyxuB\n" +
            "Oa3Qx5dtiTQOqz5pzifYcZBcwDwQYBkgiatf7n2F+EVkiOB3Su53ZL6s12TC88F0\n" +
            "K0pL/z3Nf/q/lBAySOXM9ht/uMNSITMtaL2sej5b1UeVfyfT1ZbMUfqbG1FJ7lYR\n" +
            "lYU+ZqzEVQHtKxr9kp2JJ/b0yanvV6q/CjDXsyObCCL5b7aCs41OSdVmh7w2b5pW\n" +
            "uvRIZHtLveu7MAR0lAF2uryF2BsCROjHingrY9+nILU/iBUgfm+YOxYHynoo1YP+\n" +
            "zGkCBGmwWeWjggEqMIIBJjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIEsDBVBgNV\n" +
            "HSAETjBMMEoGCysGAQQBzh8KAQEBMDswEgYIKwYBBQUHAgIwBhoEbm9uZTAlBggr\n" +
            "BgEFBQcCARYZaHR0cDovL3d3dy5zay5lZS9jcHMvbWlkLzAdBgNVHQ4EFgQUYVZu\n" +
            "/8Ks/gwuZ5vBqGXewf+UN/EwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIGCCsGAQUF\n" +
            "BwMEMBgGCCsGAQUFBwEDBAwwCjAIBgYEAI5GAQEwHwYDVR0jBBgwFoAU6Z3Rnjm9\n" +
            "Zki3hS2Lx40THXN/KBkwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5zay5l\n" +
            "ZS9jcmxzL2VpZC9laWQyMDExLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAo0E2fUXm\n" +
            "GltrIJph3tHmNhy2LIs3kfasFkxWQ9V/TCJVOXxOlrhK0XOaHUMTIM5dHI7GzsA3\n" +
            "vtBVAhL75hesBkoPIj5MhA4DD01/rhELv2ZSWfunhWBBKmIPtIoUdTgfbCjz3PW2\n" +
            "pf0MEeyISN2SM6b02+zVxelhY5kz0vqKKHJNZ+l6sNij9kIdPZc/0khNkRZK/Flx\n" +
            "Gl9G7nq5bB1Tz5Y+8wRy2RN8YFkqNe0zG4YKJ6NOFNtFOUIXvXtAr7nMtsGfjt4u\n" +
            "mGD0tmcVMk82cqQy31pcZNsxPyIiDG0A/uD3r7HoyCTRMhB8Yw2rEBkQcxngFCo2\n" +
            "PLKqdHE49O+h8Q==\n" +
            "-----END CERTIFICATE-----";

    @Test
    public void getRfc822NameSubjectAltNameShouldExtractEmailFromEsteid2015Certificate() throws Exception {
        Assert.assertEquals("mari-liis.mannik@eesti.ee" , X509Utils.getRfc822NameSubjectAltName(loadCertificate("classpath:id-card/47101010033(TEST_of_ESTEID-SK_2015).pem")));
    }

    @Test
    public void getAiaOcspUrlFrom2015Cert() throws Exception {
        Assert.assertEquals("http://aia.demo.sk.ee/esteid2015" , X509Utils.getOCSPUrl(loadCertificate("classpath:id-card/47101010033(TEST_of_ESTEID-SK_2015).pem")));
    }

    @Test
    public void getAiaOcspUrlFrom2018Cert() throws Exception {
        Assert.assertEquals("http://aia.demo.sk.ee/esteid2018" , X509Utils.getOCSPUrl(loadCertificate("classpath:id-card/38001085718(TEST_of_ESTEID2018).pem")));
    }

    @Test
    public void getAiaOcspUrlFromUnknownCert() throws Exception {
        Assert.assertEquals(null , X509Utils.getOCSPUrl(X509Utils.toX509Certificate(certWithNoSanFields)));
    }


    @Test
    public void getRfc822NameSubjectAltNameShouldExtractEmailFromEsteid2018Certificate() throws Exception {
        Assert.assertEquals("38001085718@eesti.ee" , X509Utils.getRfc822NameSubjectAltName(loadCertificate("classpath:id-card/38001085718(TEST_of_ESTEID2018).pem")));
    }

    @Test
    public void getRfc822NameSubjectAltNameShouldThrowExceptionWhenNoSanFieldsPresent() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("This certificate does not contain any Subject Alternative Name fields!");
        X509Utils.getRfc822NameSubjectAltName(X509Utils.toX509Certificate(certWithNoSanFields));
    }

    private X509Certificate loadCertificate(String resourcePath) throws CertificateException, IOException {
        Resource resource = resourceLoader.getResource(resourcePath);
        if (!resource.exists()) {
            throw new IllegalArgumentException("Could not find resource " + resourcePath);
        }

        try (InputStream inputStream = resource.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }
}
