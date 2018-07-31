package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.Principal;
import java.security.cert.X509Certificate;

@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class IDCardAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String MOCK_SERIAL_NUMBER = "60001019906";
    private static final String MOCK_GIVEN_NAME = "MARY ÄNN";
    private static final String MOCK_SURNAME = "O’CONNEŽ-ŠUSLIK";

    @Autowired
    private IDCardConfigurationProvider idcardConfigurationProvider;

    @Autowired
    private IDCardAuthenticationService authenticationService;

    @Test
    public void loginByIDCardShouldFailWhenNoCertificatePresentInSession() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Unable to find certificate from session");

        Event event = this.authenticationService.loginByIDCard(this.getRequestContext(null));
    }

    @Test
    public void loginByIDCardSucceeds() {
        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getExternalContext().getSessionMap().put(
                Constants.CERTIFICATE_SESSION_ATTRIBUTE,
                this.createMockClientCertificate()
        );

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        TaraCredential credential = (TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredential(credential);
    }

    private X509Certificate createMockClientCertificate() {
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getName()).thenReturn(String.format(
                "SERIALNUMBER=%s, GIVENNAME=%s, SURNAME=%s",
                MOCK_SERIAL_NUMBER, MOCK_GIVEN_NAME, MOCK_SURNAME
        ));

        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Mockito.when(certificate.getSubjectDN()).thenReturn(principal);

        return certificate;
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals("EE" + MOCK_SERIAL_NUMBER, credential.getId());
        Assert.assertEquals(MOCK_GIVEN_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_SURNAME, credential.getLastName());
    }

}
