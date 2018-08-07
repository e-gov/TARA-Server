package ee.ria.sso.config.mobileid;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.flow.action.MobileIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.MobileIDStartAuthenticationAction;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.mobileid.MobileIDAuthenticatorWrapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "mobile-id.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class MobileIDDisabledConfigurationTest extends AbstractDisabledConfigurationTest {

    @Test
    public void whenMobileIDDisabledThenMobileIDBeansNotInitiated() {
        assertBeanNotInitiated(MobileIDConfiguration.class);
        assertBeanNotInitiated(MobileIDAuthenticationService.class);
        assertBeanNotInitiated(MobileIDConfigurationProvider.class);
        assertBeanNotInitiated(MobileIDCheckAuthenticationAction.class);
        assertBeanNotInitiated(MobileIDStartAuthenticationAction.class);
        assertBeanNotInitiated(MobileIDAuthenticatorWrapper.class);
    }

}
