package ee.ria.sso.config.banklink;

import ee.ria.sso.config.smartid.SmartIDConfiguration;
import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.ria.sso.flow.action.SmartIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.SmartIDStartAuthenticationAction;
import ee.ria.sso.service.banklink.BanklinkAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationValidatorWrapper;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.SmartIdConnector;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.fail;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "banklinks.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestBanklinkConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class BanklinkDisabledConfigurationTest {

    @Autowired
    private ApplicationContext applicationContext;
    
    @Test
    public void whenSmartIdDisabledThenSmartIDBeansNotInitiated() {
        assertBeanNotInitiated(BanklinkConfiguration.class);
        assertBeanNotInitiated(BanklinkAuthenticationService.class);
        assertBeanNotInitiated(BanklinkConfigurationProvider.class);
    }

    private void assertBeanNotInitiated(Class clazz) {
        try {
            applicationContext.getBean(clazz);
            fail("Bean <" + clazz + "> should not be initiated!");
        } catch (NoSuchBeanDefinitionException e) {
            e.printStackTrace();
        }
    }
}
