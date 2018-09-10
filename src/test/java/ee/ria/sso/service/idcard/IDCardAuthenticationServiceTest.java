package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import ee.ria.sso.validators.OCSPValidationException;
import ee.ria.sso.validators.OCSPValidator;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
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
    public void cleanUp() {
        Mockito.reset(ocspValidatorMock);
        SimpleTestAppender.events.clear();
    }

    @Test
    public void loginByIDCardShouldFailWhenNoCertificatePresentInSession() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Unable to find certificate from session");

        try {
            Event event = this.authenticationService.loginByIDCard(this.getMockRequestContext(null));
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("Unable to find certificate from session");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenCertificateIsNotValidYet() throws Exception {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("User certificate is not yet valid");

        X509Certificate certificate = mockInvalidCertificate(new CertificateNotYetValidException());
        RequestContext requestContext = this.getMockRequestContextWith(null, certificate);

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("User certificate is not yet valid");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenCertificateIsExpired() throws Exception {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("User certificate is expired");

        X509Certificate certificate = mockInvalidCertificate(new CertificateExpiredException());
        RequestContext requestContext = this.getMockRequestContextWith(null, certificate);

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("User certificate is expired");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenOCSPValidatorThrowsException() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("OCSP validation failed");

        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate);
        Exception cause = OCSPValidationException.of(new RuntimeException());

        Mockito.doThrow(cause).when(ocspValidatorMock).validate(mockUserCertificate,
                issuerCertificates.get("TEST of ESTEID-SK 2011"),
                configurationProvider.getOcspUrl(),
                issuerCertificates
        );

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("OCSP validation failed");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardSucceeds() {
        RequestContext requestContext = this.getMockRequestContextWith(null,  mockUserCertificate);

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        TaraCredential credential = (TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredential(credential);

        this.verifyLogContentsOnSuccessfulAuthentication();
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.IDCard, credential.getType());
        Assert.assertEquals("EE" + MOCK_SERIAL_NUMBER, credential.getId());
        Assert.assertEquals(MOCK_GIVEN_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_SURNAME, credential.getLastName());
    }

    private void verifyLogContentsOnSuccessfulAuthentication() {
        AuthenticationType authenticationType = AuthenticationType.IDCard;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, StatisticsOperation.START_AUTH)),
                Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, StatisticsOperation.SUCCESSFUL_AUTH))
        );
    }

    private void verifyLogContentsOnUnsuccessfulAuthentication(String errorMessage) {
        AuthenticationType authenticationType = AuthenticationType.IDCard;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, StatisticsOperation.START_AUTH)),
                Matchers.containsString(String.format(";openIdDemo;%s;%s;%s", authenticationType, StatisticsOperation.ERROR, errorMessage))
        );
    }

    private RequestContext getMockRequestContextWith(Map<String, String> requestParameters, X509Certificate certificate) {
        RequestContext requestContext = this.getMockRequestContext(requestParameters);
        requestContext.getExternalContext().getSessionMap().put(
                Constants.CERTIFICATE_SESSION_ATTRIBUTE,
                certificate
        );

        return requestContext;
    }

    private X509Certificate mockInvalidCertificate(CertificateException exception) throws CertificateException {
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Mockito.doThrow(exception).when(certificate).checkValidity();
        return certificate;
    }

}
