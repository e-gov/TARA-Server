package ee.ria.sso.service.mobileid;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.config.mobileid.TestMobileIDConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class MobileIDAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final int MOCK_SESSION_CODE = 1123456789;
    private static final String MOCK_CHALLENGE = "mockChallenge";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_PERSONAL_CODE = "60001019906";
    private static final String MOCK_PHONE_NUMBER = "2123456789";

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    @Autowired
    private MobileIDAuthenticationService authenticationService;

    @Autowired
    private MobileIDAuthenticatorWrapper authenticatorMock;

    @After
    public void cleanUp() {
        Mockito.reset(authenticatorMock);
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoCredentialPresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("java.lang.NullPointerException");

        Event event = this.authenticationService.startLoginByMobileID(this.getRequestContext(null));
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoMobileNumberPresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("ee.ria.sso.authentication.TaraCredentialsException: Credential value <null> is invalid");

        TaraCredential credential = createCredentialWithIdAndNumber();
        credential.setMobileNumber(null);

        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoPrincipalCodePresent() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("ee.ria.sso.authentication.TaraCredentialsException: Credential value <null> is invalid");

        TaraCredential credential = createCredentialWithIdAndNumber();
        credential.setPrincipalCode(null);

        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileIDAuthenticatorStartLoginFails() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("com.codeborne.security.AuthenticationException: AUTHENTICATION_ERROR");

        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", createCredentialWithIdAndNumber()
        );

        Mockito.when(authenticatorMock.startLogin(MOCK_PERSONAL_CODE, configurationProvider.getCountryCode(), MOCK_PHONE_NUMBER))
                .thenThrow(new AuthenticationException(AuthenticationException.Code.AUTHENTICATION_ERROR));

        try {
            Event event = this.authenticationService.startLoginByMobileID(requestContext);
        } catch (Exception e) {
            this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, "AUTHENTICATION_ERROR");
            throw e;
        }

        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDSucceeds() {
        RequestContext requestContext = this.getRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", createCredentialWithIdAndNumber()
        );

        final MobileIDSession mobileIDSession = createMobileIDSession();
        Mockito.when(authenticatorMock.startLogin(MOCK_PERSONAL_CODE, configurationProvider.getCountryCode(), MOCK_PHONE_NUMBER))
                .thenReturn(mobileIDSession);

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        Assert.assertEquals("success", event.getId());

        Assert.assertEquals(MOCK_CHALLENGE, requestContext.getFlowScope().get(Constants.MOBILE_CHALLENGE));
        Assert.assertEquals(MOCK_PHONE_NUMBER, requestContext.getFlowScope().get(Constants.MOBILE_NUMBER));
        Assert.assertEquals(mobileIDSession, requestContext.getFlowScope().get(Constants.MOBILE_SESSION));
        Assert.assertEquals(0, requestContext.getFlowScope().get(Constants.AUTH_COUNT));

        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    @Test
    public void checkLoginForMobileIDSucceedsAsOutstanding() {
        final RequestContext requestContext = this.getRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenReturn(false);

        Event event = this.authenticationService.checkLoginForMobileID(requestContext);
        Assert.assertEquals("outstanding", event.getId());

        Assert.assertEquals(new Integer(1), requestContext.getFlowScope().getInteger(Constants.AUTH_COUNT));
        SimpleTestAppender.verifyNoLogEventsExist(Matchers.any(String.class));
    }

    @Test
    public void checkLoginForMobileIDSucceeds() {
        RequestContext requestContext = this.getRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenReturn(true);

        Event event = this.authenticationService.checkLoginForMobileID(requestContext);
        Assert.assertEquals("success", event.getId());

        TaraCredential credential = (TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredential(credential);

        this.verifyLogContents(StatisticsOperation.SUCCESSFUL_AUTH);
    }

    private TaraCredential createCredentialWithIdAndNumber() {
        TaraCredential taraCredential = new TaraCredential();
        taraCredential.setPrincipalCode(MOCK_PERSONAL_CODE);
        taraCredential.setMobileNumber(MOCK_PHONE_NUMBER);
        return taraCredential;
    }

    private MobileIDSession createMobileIDSession() {
        return new MobileIDSession(
                MOCK_SESSION_CODE,
                MOCK_CHALLENGE,
                MOCK_FIRST_NAME,
                MOCK_LAST_NAME,
                MOCK_PERSONAL_CODE
        );
    }

    private void fillRequestContextFlowScope(RequestContext requestContext, MobileIDSession mobileIDSession, int authCount) {
        requestContext.getFlowScope().put(Constants.MOBILE_CHALLENGE, mobileIDSession.challenge);
        requestContext.getFlowScope().put(Constants.MOBILE_NUMBER, MOCK_PHONE_NUMBER);
        requestContext.getFlowScope().put(Constants.MOBILE_SESSION, mobileIDSession);
        requestContext.getFlowScope().put(Constants.AUTH_COUNT, authCount);
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        Assert.assertEquals(AuthenticationType.MobileID, credential.getType());
        Assert.assertEquals("EE" + MOCK_PERSONAL_CODE, credential.getId());
        Assert.assertEquals(MOCK_FIRST_NAME, credential.getFirstName());
        Assert.assertEquals(MOCK_LAST_NAME, credential.getLastName());
        Assert.assertEquals("+372" + MOCK_PHONE_NUMBER, credential.getMobileNumber());
    }

    private void verifyLogContents(StatisticsOperation statisticsOperation) {
        AuthenticationType authenticationType = AuthenticationType.MobileID;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, statisticsOperation))
        );
    }

    private void verifyLogContentsOnFailure(StatisticsOperation precedingOperation, String errorMessage) {
        AuthenticationType authenticationType = AuthenticationType.MobileID;

        SimpleTestAppender.verifyLogEventsExistInOrder(
                Matchers.containsString(String.format(";openIdDemo;%s;%s;", authenticationType, precedingOperation)),
                Matchers.containsString(String.format(";openIdDemo;%s;%s;%s", authenticationType, StatisticsOperation.ERROR, errorMessage))
        );
    }

}
