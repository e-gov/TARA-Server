package ee.ria.sso.config;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties")
@RunWith(SpringRunner.class)
@ContextConfiguration(
        classes = TestTaraConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class IncidentLoggingConfigurationTest {

    @Autowired
    ApplicationContext applicationContext;

    @Test
    public void testIncidentLoggingMDCServletFilterPresence() {
        Assert.assertNotNull(applicationContext.getBean("incidentLoggingMDCServletFilter"));
    }

}
