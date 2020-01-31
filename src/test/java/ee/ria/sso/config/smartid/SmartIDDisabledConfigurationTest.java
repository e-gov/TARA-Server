package ee.ria.sso.config.smartid;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.flow.action.SmartIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.SmartIDCheckCancelAction;
import ee.ria.sso.flow.action.SmartIDStartAuthenticationAction;
import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationValidatorWrapper;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.SmartIdConnector;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(locations= "classpath:application-test-smart-id-disabled.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestSmartIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class SmartIDDisabledConfigurationTest extends AbstractDisabledConfigurationTest {
    
    @Test
    public void whenSmartIdDisabledThenSmartIDBeansNotInitiated() {
        assertBeanNotInitiated(SmartIDConfiguration.class);
        assertBeanNotInitiated(SmartIDConfigurationProvider.class);
        assertBeanNotInitiated(SmartIDAuthenticationService.class);
        assertBeanNotInitiated(SmartIDAuthenticationValidatorWrapper.class);
        assertBeanNotInitiated(AuthenticationResponseValidator.class);
        assertBeanNotInitiated(SmartIdClient.class);
        assertBeanNotInitiated(SmartIdConnector.class);
        assertBeanNotInitiated(ClientConfig.class);
        assertBeanNotInitiated(SmartIDCheckAuthenticationAction.class);
        assertBeanNotInitiated(SmartIDStartAuthenticationAction.class);
        assertBeanNotInitiated(SmartIDCheckCancelAction.class);
    }
}
