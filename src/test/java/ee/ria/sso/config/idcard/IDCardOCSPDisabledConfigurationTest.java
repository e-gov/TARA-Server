package ee.ria.sso.config.idcard;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "id-card.ocsp-enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class IDCardOCSPDisabledConfigurationTest extends AbstractDisabledConfigurationTest {

    @Test
    public void whenIDCardDisabledThenIDCardBeansNotInitiated() {
        assertBeanNotInitiated("idCardTrustedCertificatesMap");
    }

}
