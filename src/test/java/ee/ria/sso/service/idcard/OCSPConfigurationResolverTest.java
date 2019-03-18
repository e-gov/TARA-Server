package ee.ria.sso.service.idcard;

import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static ee.ria.sso.config.idcard.IDCardConfigurationProvider.Ocsp.*;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class OCSPConfigurationResolverTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    @Qualifier("mockIDCardUserCertificate2015")
    private X509Certificate mockUserCertificate2015;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2011")
    private X509Certificate mockUserCertificate2011;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2018")
    private X509Certificate mockUserCertificate2018;

    @Mock
    private IDCardConfigurationProvider idCardConfigurationProvider;

    @Test
    public void resolveShouldFailWhenNoUserCertProvided() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("User certificate is missing!");

        new OCSPConfigurationResolver(idCardConfigurationProvider).resolve(null);
    }

    @Test
    public void resolveShouldFailWithNoExplicitlyDefinedConfigurationAndNoAiaOcspExtension() {
        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("OCSP configuration invalid! This user certificate's issuer, " +
                "issued by 'TEST of ESTEID-SK 2011', has no explicitly configured OCSP " +
                "nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration");

        new OCSPConfigurationResolver(idCardConfigurationProvider).resolve(mockUserCertificate2011);
    }

    @Test
    public void resolveShouldSucceedWithEsteid2018CertWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        List<IDCardConfigurationProvider.Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        Assert.assertEquals(1, conf.size());
        Assert.assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        Assert.assertEquals(false, conf.get(0).isNonceDisabled());
        Assert.assertEquals(null, conf.get(0).getResponderCertificateCn());
        Assert.assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        Assert.assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithEsteid2015CertWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        List<IDCardConfigurationProvider.Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2015);

        Assert.assertEquals(1, conf.size());
        Assert.assertEquals("http://aia.demo.sk.ee/esteid2015", conf.get(0).getUrl());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID-SK 2015"), conf.get(0).getIssuerCn());
        Assert.assertEquals(false, conf.get(0).isNonceDisabled());
        Assert.assertEquals(null, conf.get(0).getResponderCertificateCn());
        Assert.assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        Assert.assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithEsteid2018CertAndExplicitlyDefinedConfiguration() {
        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        true, 3, 901, 1111, 2222,
                        "Responder.pem")
        ));

        List<IDCardConfigurationProvider.Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        Assert.assertEquals(1, conf.size());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        Assert.assertEquals("http://localhost:1234/ocsp", conf.get(0).getUrl());
        Assert.assertEquals(true, conf.get(0).isNonceDisabled());
        Assert.assertEquals("Responder.pem", conf.get(0).getResponderCertificateCn());
        Assert.assertEquals(3, conf.get(0).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(901, conf.get(0).getResponseLifetimeInSeconds());
        Assert.assertEquals(1111, conf.get(0).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(2222, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithFallbackOcsp() {
        Mockito.when(idCardConfigurationProvider.getFallbackOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem")
        ));


        List<IDCardConfigurationProvider.Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        Assert.assertEquals(2, conf.size());

        Assert.assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        Assert.assertEquals(false, conf.get(0).isNonceDisabled());
        Assert.assertEquals(null, conf.get(0).getResponderCertificateCn());
        Assert.assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        Assert.assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        Assert.assertEquals("http://localhost:1234/ocsp", conf.get(1).getUrl());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        Assert.assertEquals(false, conf.get(1).isNonceDisabled());
        Assert.assertEquals("TEST_of_SK_OCSP_RESPONDER_2011.pem", conf.get(1).getResponderCertificateCn());
        Assert.assertEquals(3, conf.get(1).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(901, conf.get(1).getResponseLifetimeInSeconds());
        Assert.assertEquals(1111, conf.get(1).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(2222, conf.get(1).getReadTimeoutInMilliseconds());
    }


    private IDCardConfigurationProvider.Ocsp getMockOcspConfiguration(List<String> issuerCn, String url, boolean nonceDisabled, int acceptedClockSkewInSeconds, int responseLifetimeInSeconds, int connectTimeoutInMilliseconds, int readTimeoutInMilliseconds, String responderCertificate) {
        IDCardConfigurationProvider.Ocsp ocspConfiguration = new IDCardConfigurationProvider.Ocsp();
        ocspConfiguration.setIssuerCn(issuerCn);
        ocspConfiguration.setUrl(url);
        ocspConfiguration.setNonceDisabled(nonceDisabled);
        ocspConfiguration.setAcceptedClockSkewInSeconds(acceptedClockSkewInSeconds);
        ocspConfiguration.setResponseLifetimeInSeconds(responseLifetimeInSeconds);
        ocspConfiguration.setConnectTimeoutInMilliseconds(connectTimeoutInMilliseconds);
        ocspConfiguration.setReadTimeoutInMilliseconds(readTimeoutInMilliseconds);
        ocspConfiguration.setResponderCertificateCn(responderCertificate);
        return ocspConfiguration;
    }
}
