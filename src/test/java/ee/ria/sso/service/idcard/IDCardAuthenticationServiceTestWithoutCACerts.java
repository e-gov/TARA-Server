package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.test.SimpleTestAppender;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.cert.X509Certificate;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "id-card.ocsp-certificates=" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class IDCardAuthenticationServiceTestWithoutCACerts extends AbstractAuthenticationServiceTest {

    @Autowired
    private IDCardAuthenticationService authenticationService;

    @Autowired
    @Qualifier("mockIDCardUserCertificate")
    private X509Certificate mockUserCertificate;

    @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void loginByIDCardShouldFailWhenNoCACertsConfigured() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Issuer cert not found from setup");

        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getExternalContext().getSessionMap().put(
                Constants.CERTIFICATE_SESSION_ATTRIBUTE,
                mockUserCertificate
        );

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.fail("Should not reach this!");
    }

}
