package ee.ria.sso.config.eidas;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.flow.action.EidasCheckAuthenticationAction;
import ee.ria.sso.flow.action.EidasStartAuthenticationAction;
import ee.ria.sso.service.eidas.EidasAuthenticationService;
import ee.ria.sso.service.eidas.EidasAuthenticator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "eidas.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestEidasConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class EidasDisabledConfigurationTest extends AbstractDisabledConfigurationTest {

    @Test
    public void whenEidasDisabledThenEidasBeansNotInitiated() {
        assertBeanNotInitiated(EidasConfiguration.class);
        assertBeanNotInitiated(EidasAuthenticationService.class);
        assertBeanNotInitiated(EidasConfigurationProvider.class);
        assertBeanNotInitiated(EidasCheckAuthenticationAction.class);
        assertBeanNotInitiated(EidasStartAuthenticationAction.class);
        assertBeanNotInitiated(EidasAuthenticator.class);
    }

}
