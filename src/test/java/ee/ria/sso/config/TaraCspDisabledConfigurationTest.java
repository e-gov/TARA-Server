package ee.ria.sso.config;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        properties = { "security.csp.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestTaraCspConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class TaraCspDisabledConfigurationTest extends AbstractDisabledConfigurationTest {

    @Test
    public void whenCspDisabledThenCspBeansNotInitiated() {
        assertBeanNotInitiated("taraCspResponseHeadersEnforcementFilter");
        assertBeanNotInitiated(TaraCspConfiguration.class);
    }

}
