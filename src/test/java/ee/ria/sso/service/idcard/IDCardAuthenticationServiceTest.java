package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.config.idcard.TestIDCardConfiguration;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

@ContextConfiguration(
        classes = TestIDCardConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class IDCardAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    @Autowired
    private IDCardConfigurationProvider configurationProvider;

    @Autowired
    private IDCardAuthenticationService authenticationService;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2015")
    private X509Certificate mockUserCertificate2015;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2011")
    private X509Certificate mockUserCertificate2011;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2018")
    private X509Certificate mockUserCertificate2018;

    @Autowired
    private OCSPValidator ocspValidatorMock;

    @Captor
    ArgumentCaptor<IDCardConfigurationProvider.Ocsp> ocspConfiguration;



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
    public void loginByIDCardShouldFailWhenOCSPValidatorThrowsUnexcpectedException() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Unexpected exception");

        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2015);
        Exception cause = new RuntimeException("Unexpected exception");

        Mockito.doThrow(cause).when(ocspValidatorMock).checkCert(Mockito.eq(mockUserCertificate2015));

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("Unexpected exception");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenOCSPValidatorThrowsOCSPConnectionFailedException() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("OCSP service is currently not available, please try again later");

        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2015);
        Exception cause = new OCSPServiceNotAvailableException(new SocketTimeoutException("timeout"));

        Mockito.doThrow(cause).when(ocspValidatorMock).checkCert(Mockito.eq(mockUserCertificate2015));

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("OCSP service is currently not available, please try again later");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCardShouldFailWhenOCSPValidatorThrowsOCSPValidationFailedException() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid certificate status <REVOKED> received");

        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2015);
        Exception cause = OCSPValidationException.of(CertificateStatus.REVOKED);

        Mockito.doThrow(cause).when(ocspValidatorMock).checkCert(Mockito.eq(mockUserCertificate2015));

        try {
            Event event = this.authenticationService.loginByIDCard(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnUnsuccessfulAuthentication("Invalid certificate status <REVOKED> received");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void loginByIDCard2015Succeeds() {
        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2015);

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        IdCardCredential credential = (IdCardCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredentialWithoutEmail(credential, "47101010033", "MARI-LIIS", "MÄNNIK");

        this.verifyLogContentsOnSuccessfulAuthentication();
    }

    @Test
    public void loginByIDCard2018Succeeds() {
        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2018);

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        IdCardCredential credential = (IdCardCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredentialWithoutEmail(credential, "38001085718", "JAAK-KRISTJAN", "JÕEORG");

        this.verifyLogContentsOnSuccessfulAuthentication();
    }

    @Test
    public void loginByIDCard2018SucceedsWithAiaOcsp() {
        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2018);

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        IdCardCredential credential = (IdCardCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredentialWithoutEmail(credential, "38001085718", "JAAK-KRISTJAN", "JÕEORG");

        this.verifyLogContentsOnSuccessfulAuthentication();
    }

    @Test
    public void loginByIDCard2011SucceedsWithAiaOcsp() {
        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2011);

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        IdCardCredential credential = (IdCardCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredentialWithoutEmail(credential, "48812040138", "KRÕÕT", "VÄRNICK");

        this.verifyLogContentsOnSuccessfulAuthentication();

        Mockito.verify(ocspValidatorMock).checkCert(Mockito.eq(mockUserCertificate2011));
    }

    @Test
    public void loginByIDCard2018SucceedsEmailScopeProvided() {
        RequestContext requestContext = this.getMockRequestContextWith(null, mockUserCertificate2018);
        requestContext.getExternalContext().getSessionMap().put(Constants.TARA_OIDC_SESSION_SCOPES, Collections.singletonList(TaraScope.EMAIL));

        Event event = this.authenticationService.loginByIDCard(requestContext);
        Assert.assertEquals("success", event.getId());

        IdCardCredential credential = (IdCardCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredentialWithEmail(credential, "38001085718", "JAAK-KRISTJAN", "JÕEORG", "38001085718@eesti.ee", false);

        this.verifyLogContentsOnSuccessfulAuthentication();
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

    private void assertTaraCredential(IdCardCredential credential, String serialNumber, String givenName, String surname) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.IDCard, credential.getType());
        Assert.assertEquals("EE" + serialNumber, credential.getId());
        Assert.assertEquals(givenName, credential.getFirstName());
        Assert.assertEquals(surname, credential.getLastName());
    }

    private void validateUserCredentialWithEmail(IdCardCredential credential, String serialNumber, String givenName, String surname, String email, boolean emailVerified) {
        assertTaraCredential(credential, serialNumber, givenName, surname);
        Assert.assertEquals(emailVerified, credential.getEmailVerified());
        Assert.assertEquals(email, credential.getEmail());
    }

    private void validateUserCredentialWithoutEmail(IdCardCredential credential, String serialNumber, String givenName, String surname) {
        assertTaraCredential(credential, serialNumber, givenName, surname);
        Assert.assertEquals(false, credential.getEmailVerified());
        Assert.assertNull("e-mail should not be present", credential.getEmail());
    }
}
