package ee.ria.sso.config.mobileid;

import ee.ria.sso.config.AbstractDisabledConfigurationTest;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.action.MobileIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.MobileIDStartAuthenticationAction;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTAuthClient;
import ee.ria.sso.service.mobileid.soap.MobileIDSOAPAuthClient;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.mid.MidDisplayTextFormat;
import ee.sk.mid.MidHashType;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "mobile-id.enabled=true", "mobile-id.use-dds-service=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class MobileIDRESTProtocolConfigurationTest extends AbstractDisabledConfigurationTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    @Test
    public void configurationParametersRead() {
        assertTrue(configurationProvider.isEnabled());
        assertEquals("https://random.test.url.ee/mid-api", configurationProvider.getHostUrl());
        assertEquals("EE", configurationProvider.getCountryCode());
        assertEquals("EST", configurationProvider.getLanguage());
        assertEquals("+372", configurationProvider.getAreaCode());
        assertEquals("Test value - service name", configurationProvider.getServiceName());
        assertEquals("Test value - message to display", configurationProvider.getMessageToDisplay());
        assertSame(MidDisplayTextFormat.UCS2, configurationProvider.getMessageToDisplayEncoding());
        assertSame(MidHashType.SHA256, configurationProvider.getAuthenticationHashType());
        assertEquals("Test value - 00000000-0000-0000-0000-000000000000", configurationProvider.getRelyingPartyUuid());
        assertEquals("Test value - DEMO", configurationProvider.getRelyingPartyName());
        assertEquals(Integer.valueOf(1), configurationProvider.getSessionStatusSocketOpenDuration());
        assertEquals(Integer.valueOf(2345), configurationProvider.getTimeoutBetweenSessionStatusQueries());
        assertEquals(Integer.valueOf(2501), configurationProvider.getReadTimeout());
        assertEquals(Integer.valueOf(2501), configurationProvider.getConnectionTimeout());
        assertFalse(configurationProvider.isUseDdsService());
    }

    @Test
    public void connectionTimeOutSmallerThanSessionStatusSocketOpenDuration_exceptionThrown() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Network connection timeout(<3459>) should not be shorter than sum of session status check socket open duration(<3000>) and connection duration margin (<1500>)");

        MobileIDConfigurationProvider confProvider = new MobileIDConfigurationProvider();
        confProvider.setSessionStatusSocketOpenDuration(3000);
        confProvider.setConnectionTimeout(3459);
        confProvider.init();
    }

    @Test
    public void relyingPartyUUIDMandatoryIfUsingRESTProtocol() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'mobile-id.relying-party-uuid' cannot be blank when using MID-REST protocol ('mobile-id.use-dds-service=false')");

        MobileIDConfigurationProvider confProvider = new MobileIDConfigurationProvider();
        confProvider.setUseDdsService(false);
        confProvider.setRelyingPartyUuid(null);
        confProvider.setRelyingPartyName("Not blank");
        confProvider.init();
    }

    @Test
    public void relyingPartyNameMandatoryIfUsingRESTProtocol() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("'mobile-id.relying-party-name' cannot be blank when using MID-REST protocol ('mobile-id.use-dds-service=false')");

        MobileIDConfigurationProvider confProvider = new MobileIDConfigurationProvider();
        confProvider.setUseDdsService(false);
        confProvider.setRelyingPartyUuid("Not blank");
        confProvider.setRelyingPartyName(null);
        confProvider.init();
    }

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

        assertFalse(configurationProvider.isUseDdsService());
        assertBeanInitiated(MobileIDRESTAuthClient.class);
        assertBeanNotInitiated(MobileIDSOAPAuthClient.class);
    }
}
