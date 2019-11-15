package ee.ria.sso.config.smartid;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.action.SmartIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.SmartIDStartAuthenticationAction;
import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationValidatorWrapper;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.rest.SmartIdConnector;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestSmartIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class SmartIDConfigurationProviderTest extends AbstractDisabledConfigurationTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Autowired
    private SmartIDConfigurationProvider configurationProvider;

    @Test
    public void configurationParametersRead() {
        assertEquals(HashType.SHA512, configurationProvider.getAuthenticationHashType());
        assertEquals("TEST", configurationProvider.getAuthenticationConsentDialogDisplayText());
        assertEquals("some-rp-name", configurationProvider.getRelyingPartyName());
        assertEquals("some-rp-uuid", configurationProvider.getRelyingPartyUuid());
        assertEquals(new Integer(3000), configurationProvider.getSessionStatusSocketOpenDuration());
        assertEquals(new Integer(5000), configurationProvider.getConnectionTimeout());
        assertEquals(new Integer(30000), configurationProvider.getReadTimeout());
        assertEquals("http://localhost:8080", configurationProvider.getHostUrl());
        assertEquals("classpath:ocsp", configurationProvider.getTrustedCaCertificatesLocation());
        assertEquals(
                Arrays.asList("TEST_of_EID-SK_2016.crt", "TEST_of_NQ-SK_2016.crt", "EID-SK_2016.crt", "NQ-SK_2016.crt"),
                configurationProvider.getTrustedCaCertificates());
    }

    @Test
    public void connectionTimeOutSmallerThanSessionStatusSocketOpenDuration_exceptionThrown() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Network connection timeout(<2999>) should not be shorter than session status check socket open duration(<3000>)");

        SmartIDConfigurationProvider confProvider = new SmartIDConfigurationProvider();
        confProvider.setSessionStatusSocketOpenDuration(3000);
        confProvider.setConnectionTimeout(2999);
        confProvider.init();
    }

    @Test
    public void sessionStatusSocketOpenRoundedUpTo1000() {
        SmartIDConfigurationProvider confProvider = new SmartIDConfigurationProvider();
        confProvider.setSessionStatusSocketOpenDuration(400);
        confProvider.init();

        assertEquals(Integer.valueOf(1000), confProvider.getSessionStatusSocketOpenDuration());
    }

    @Test
    public void whenSmartIdEnabledThenItsRequiredBeansInitiated() {
        assertTrue(configurationProvider.isEnabled());
        assertBeanInitiated(SmartIDConfiguration.class);
        assertBeanInitiated(SmartIDConfigurationProvider.class);
        assertBeanInitiated(SmartIDAuthenticationService.class);
        assertBeanInitiated(SmartIDAuthenticationValidatorWrapper.class);
        assertBeanInitiated(AuthenticationResponseValidator.class);
        assertBeanInitiated(SmartIdConnector.class);
        assertBeanInitiated(ClientConfig.class);
        assertBeanInitiated(SmartIDCheckAuthenticationAction.class);
        assertBeanInitiated(SmartIDStartAuthenticationAction.class);
        assertBeanInitiated(StatisticsHandler.class);
        assertBeanInitiated(TaraResourceBundleMessageSource.class);
    }
}
