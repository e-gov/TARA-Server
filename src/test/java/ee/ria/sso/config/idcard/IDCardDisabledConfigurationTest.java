package ee.ria.sso.config.idcard;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.flow.action.IDCardAuthenticationAction;
import ee.ria.sso.service.idcard.IDCardAuthenticationService;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "id-card.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class IDCardDisabledConfigurationTest extends AbstractDisabledConfigurationTest {

    @Test
    public void whenIDCardDisabledThenIDCardBeansNotInitiated() {
        assertBeanNotInitiated(IDCardConfiguration.class);
        assertBeanNotInitiated(IDCardAuthenticationService.class);
        assertBeanNotInitiated(IDCardConfigurationProvider.class);
        assertBeanNotInitiated(IDCardAuthenticationAction.class);
    }

}
