package ee.ria.sso.config.mobileid;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.action.MobileIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.MobileIDStartAuthenticationAction;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTAuthClient;
import ee.ria.sso.service.mobileid.soap.MobileIDSOAPAuthClient;
import ee.ria.sso.statistics.StatisticsHandler;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertTrue;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "mobile-id.enabled=true", "mobile-id.use-dds-service=true" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class MobileIDSOAPProtocolConfigurationTest extends AbstractDisabledConfigurationTest {

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    @Test
    public void whenMobileIdEnabledThenItsRequiredBeansInitiated() {
        assertTrue(configurationProvider.isEnabled());
        assertBeanInitiated(MobileIDConfiguration.class);
        assertBeanInitiated(MobileIDConfigurationProvider.class);
        assertBeanInitiated(MobileIDAuthenticationService.class);
        assertBeanInitiated(MobileIDCheckAuthenticationAction.class);
        assertBeanInitiated(MobileIDStartAuthenticationAction.class);
        assertBeanInitiated(StatisticsHandler.class);
        assertBeanInitiated(TaraResourceBundleMessageSource.class);

        assertTrue(configurationProvider.isUseDdsService());
        assertBeanNotInitiated(MobileIDRESTAuthClient.class);
        assertBeanInitiated(MobileIDSOAPAuthClient.class);
    }

    @Test
    public void relyingPartyNameAndUUIDCanBeBlankIfUsingSOAPProtocol() {
        MobileIDConfigurationProvider confProvider = new MobileIDConfigurationProvider();
        confProvider.setUseDdsService(true);
        confProvider.setServiceName("Some service name");
        confProvider.setRelyingPartyName(null);
        confProvider.setRelyingPartyUuid(null);
        confProvider.init();
    }
}
