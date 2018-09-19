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
        "id-card.ocsp-url=https://test.ocsp.url",
        "id-card.ocsp-certificate-location=classpath:ocsp",
        "id-card.ocsp-certificates=TEST_of_ESTEID-SK_2015.crt,TEST_of_ESTEID2018.crt",
        "id-card.ocsp-accepted-clock-skew=13",
        "id-card.ocsp-response-lifetime=759"
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
        Assert.assertEquals("https://test.ocsp.url", configurationProvider.getOcspUrl());
        Assert.assertEquals("classpath:ocsp", configurationProvider.getOcspCertificateLocation());
        Assert.assertEquals(Arrays.asList("TEST_of_ESTEID-SK_2015.crt","TEST_of_ESTEID2018.crt"), configurationProvider.getOcspCertificates());
        Assert.assertEquals(13, configurationProvider.getOcspAcceptedClockSkew());
        Assert.assertEquals(759, configurationProvider.getOcspResponseLifetime());
    }

}
