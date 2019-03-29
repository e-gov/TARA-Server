package ee.ria.sso.config.idcard;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Arrays;

@TestPropertySource(properties = {
        "id-card.enabled=true",
        "id-card.ocsp-enabled=true",
        "id-card.truststore=classpath:/id-card/idcard-truststore-test.p12",
        "id-card.truststore-type=PKCS12",
        "id-card.truststore-pass=changeit",
        "id-card.ocsp[0].url=http://aia.sk.ee/esteid2015",
        "id-card.ocsp[0].issuer-cn=TEST of ESTEID-SK 2015",
        "id-card.ocsp[0].accepted-clock-skew-in-seconds=5",
        "id-card.ocsp[0].response-lifetime-in-seconds=60",
        "id-card.ocsp[0].connect-timeout-in-milliseconds=5000",
        "id-card.ocsp[0].read-timeout-in-milliseconds=5000",
        "id-card.ocsp[0].responder-certificate-cn=TEST of SK OCSP RESPONDER 2011",
        "id-card.fallback-ocsp[0].url=http://demo.ocsp.sk.ee/",
        "id-card.fallback-ocsp[0].issuer-cn=TEST of ESTEID-SK 2015,TEST of ESTEID-SK 2011",
        "id-card.fallback-ocsp[0].responder-certificate-cn=TEST of SK OCSP RESPONDER 2011"
})
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class IDCardConfigurationProviderTest {

    @Autowired
    IDCardConfigurationProvider configurationProvider;

    @Test
    public void testConfigurationPropertiesValues() {
        Assert.assertTrue(configurationProvider.isOcspEnabled());
        Assert.assertEquals(1, configurationProvider.getOcsp().size());

        Assert.assertEquals(configurationProvider.getTruststore(), "classpath:/id-card/idcard-truststore-test.p12");
        Assert.assertEquals(configurationProvider.getTruststoreType(), "PKCS12");
        Assert.assertEquals(configurationProvider.getTruststorePass(), "changeit");

        Assert.assertEquals(Arrays.asList("TEST of ESTEID-SK 2015"), configurationProvider.getOcsp().get(0).getIssuerCn());
        Assert.assertEquals("http://aia.sk.ee/esteid2015", configurationProvider.getOcsp().get(0).getUrl());
        Assert.assertEquals(5, configurationProvider.getOcsp().get(0).getAcceptedClockSkewInSeconds());
        Assert.assertEquals(60, configurationProvider.getOcsp().get(0).getResponseLifetimeInSeconds());
        Assert.assertEquals(5000, configurationProvider.getOcsp().get(0).getConnectTimeoutInMilliseconds());
        Assert.assertEquals(5000, configurationProvider.getOcsp().get(0).getReadTimeoutInMilliseconds());
        Assert.assertEquals("TEST of SK OCSP RESPONDER 2011", configurationProvider.getOcsp().get(0).getResponderCertificateCn());

        Assert.assertEquals(1, configurationProvider.getFallbackOcsp().size());
        Assert.assertEquals(Arrays.asList("TEST of ESTEID-SK 2015", "TEST of ESTEID-SK 2011"), configurationProvider.getFallbackOcsp().get(0).getIssuerCn());
        Assert.assertEquals("http://demo.ocsp.sk.ee/", configurationProvider.getFallbackOcsp().get(0).getUrl());
        Assert.assertEquals("TEST of SK OCSP RESPONDER 2011", configurationProvider.getFallbackOcsp().get(0).getResponderCertificateCn());
    }

}
