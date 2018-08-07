package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.validators.OCSPValidationException;
import ee.ria.sso.validators.OCSPValidator;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Map;

@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class IDCardAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String MOCK_SERIAL_NUMBER = "47101010033";
    private static final String MOCK_GIVEN_NAME = "MARI-LIIS";
    private static final String MOCK_SURNAME = "MÄNNIK";

    @Autowired
    private IDCardConfigurationProvider configurationProvider;

    @Autowired
    private IDCardAuthenticationService authenticationService;

    @Autowired
    @Qualifier("idIssuerCertificatesMap")
    private Map<String, X509Certificate> issuerCertificates;

    @Autowired
    @Qualifier("mockIDCardUserCertificate")
    private X509Certificate mockUserCertificate;

    @Autowired
    private OCSPValidator ocspValidatorMock;

    @After
    public void clearOCSPValidatorMock() {
        Mockito.reset(ocspValidatorMock);
    }

    @Test
    public void loginByIDCardShouldFailWhenNoCertificatePresentInSession() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Unable to find certificate from session");

        Event event = this.authenticationService.loginByIDCard(this.getRequestContext(null));
        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenOCSPValidatorThrowsException() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Validation failed!");

        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getExternalContext().getSessionMap().put(
                Constants.CERTIFICATE_SESSION_ATTRIBUTE,
                mockUserCertificate
        );

        String message = "Validation failed!";
        Exception cause = OCSPValidationException.of(new RuntimeException(message));
        Mockito.doThrow(new TaraAuthenticationException(message, cause)).when(ocspValidatorMock)
                .validate(mockUserCertificate, issuerCertificates.get("TEST of ESTEID-SK 2011"), configurationProvider.getOcspUrl());

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardSucceeds() {
        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getExternalContext().getSessionMap().put(
                Constants.CERTIFICATE_SESSION_ATTRIBUTE,
                mockUserCertificate
        );

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        TaraCredential credential = (TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredential(credential);
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.IDCard, credential.getType());
        Assert.assertEquals("EE" + MOCK_SERIAL_NUMBER, credential.getId());
        Assert.assertEquals(MOCK_GIVEN_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_SURNAME, credential.getLastName());
    }

}
