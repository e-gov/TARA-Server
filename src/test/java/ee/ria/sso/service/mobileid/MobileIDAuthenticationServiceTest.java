package ee.ria.sso.service.mobileid;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.config.mobileid.TestMobileIDConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.TaraAuthenticationException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.mobileid.soap.MobileIDAuthenticatorWrapper;
import ee.ria.sso.service.mobileid.soap.MobileIDSOAPAuthClient;
import ee.ria.sso.service.mobileid.soap.MobileIDSOAPSession;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.net.SocketTimeoutException;
import java.util.Arrays;

import static com.codeborne.security.AuthenticationException.Code.AUTHENTICATION_ERROR;
import static com.codeborne.security.AuthenticationException.Code.CERTIFICATE_REVOKED;
import static com.codeborne.security.AuthenticationException.Code.EXPIRED_TRANSACTION;
import static com.codeborne.security.AuthenticationException.Code.INTERNAL_ERROR;
import static com.codeborne.security.AuthenticationException.Code.INVALID_INPUT;
import static com.codeborne.security.AuthenticationException.Code.METHOD_NOT_ALLOWED;
import static com.codeborne.security.AuthenticationException.Code.MID_NOT_READY;
import static com.codeborne.security.AuthenticationException.Code.MISSING_INPUT;
import static com.codeborne.security.AuthenticationException.Code.NOT_ACTIVATED;
import static com.codeborne.security.AuthenticationException.Code.NOT_VALID;
import static com.codeborne.security.AuthenticationException.Code.NO_AGREEMENT;
import static com.codeborne.security.AuthenticationException.Code.PHONE_ABSENT;
import static com.codeborne.security.AuthenticationException.Code.SENDING_ERROR;
import static com.codeborne.security.AuthenticationException.Code.SERVICE_ERROR;
import static com.codeborne.security.AuthenticationException.Code.SIM_ERROR;
import static com.codeborne.security.AuthenticationException.Code.UNABLE_TO_TEST_USER_CERTIFICATE;
import static com.codeborne.security.AuthenticationException.Code.USER_CANCEL;
import static com.codeborne.security.AuthenticationException.Code.USER_CERTIFICATE_MISSING;
import static com.codeborne.security.AuthenticationException.Code.USER_PHONE_ERROR;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.eq;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "mobile-id.use-dds-service=true" })
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class MobileIDAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final int MOCK_SESSION_CODE = 1123456789;
    private static final String MOCK_VERIFICATION_CODE = "mockVerificationCode";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_PERSONAL_CODE = "60001019906";
    private static final String MOCK_PHONE_NUMBER = "2123456789";
    private static final String MOCK_PHONE_NUMBER_WITH_AREA_CODE = "+372" + MOCK_PHONE_NUMBER;
    private static final String MOCK_COUNTRY_CODE = "EE";

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    @Autowired
    private StatisticsHandler statisticsHandler;

    private MobileIDAuthenticationService authenticationService;

    private MobileIDAuthenticationClient authenticationClient;

    @Mock
    private MobileIDAuthenticatorWrapper authenticatorMock;

    @Before
    public void setUp() {
        Mockito.reset(authenticatorMock);
        authenticationClient = new MobileIDSOAPAuthClient(authenticatorMock);
        authenticationService = new MobileIDAuthenticationService(statisticsHandler, configurationProvider, authenticationClient);
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoCredentialPresent() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("PreAuthenticationCredential is missing!");

        Event event = this.authenticationService.startLoginByMobileID(this.getMockRequestContext(null));
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoMobileNumberPresent() {
        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided invalid mobileNumber: <null>");

        PreAuthenticationCredential credential = createCredentialWithIdAndNumber();
        credential.setMobileNumber(null);

        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenNoPrincipalCodePresent() {
        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided invalid identityCode: <null>");

        PreAuthenticationCredential credential = createCredentialWithIdAndNumber();
        credential.setPrincipalCode(null);

        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", credential
        );

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        Assert.fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileIDAuthenticatorStartLoginFailsWithServiceProblems() {
        for (AuthenticationException.Code code : Arrays.asList(AUTHENTICATION_ERROR,
                USER_CERTIFICATE_MISSING, UNABLE_TO_TEST_USER_CERTIFICATE)) {
            verifyStartLoginError(code, "Technical problems with DDS! DDS MobileAuthenticate returned an error (code: " + code + ")", "message.mid.error", ExternalServiceHasFailedException.class);
        }
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileIDAuthenticatorStartLoginFailsWithUserProblems() {
        for (AuthenticationException.Code code : Arrays.asList(USER_PHONE_ERROR,
                NO_AGREEMENT, CERTIFICATE_REVOKED, NOT_ACTIVATED, NOT_VALID)) {
            verifyStartLoginError(code, "User authentication failed! DDS MobileAuthenticate returned an error (code: " + code + ")", String.format("message.mid.%s", code.name().toLowerCase().replace("_", "")), UserAuthenticationFailedException.class);
        }
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileIDAuthenticatorStartLoginFailsWithIntegrationProblems() {
        for (AuthenticationException.Code code : Arrays.asList(SERVICE_ERROR,
                INVALID_INPUT, MISSING_INPUT, METHOD_NOT_ALLOWED)) {

            SimpleTestAppender.events.clear();
            RequestContext requestContext = this.getMockRequestContext(null);
            requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                    "credential", createCredentialWithIdAndNumber()
            );

            Mockito.when(authenticatorMock.startLogin(eq(MOCK_PERSONAL_CODE), eq(MOCK_COUNTRY_CODE), eq(MOCK_PHONE_NUMBER_WITH_AREA_CODE)))
                    .thenThrow(new AuthenticationException(code));

            try {
                this.authenticationService.startLoginByMobileID(requestContext);
                Assert.fail("Should not reach this!");
            } catch (Exception e) {
                assertThat(e, instanceOf(IllegalStateException.class));
                assertThat(e.getMessage(), containsString("Unexpected error returned by DDS MobileAuthenticate (code: " + code+ ")!"));
                this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, code.name().toUpperCase());
            }
        }
    }

    @Test
    public void startLoginByMobileIDShouldFailsWithUnexpectedError() {
        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", createCredentialWithIdAndNumber()
        );


        Mockito.when(authenticatorMock.startLogin(eq(MOCK_PERSONAL_CODE), eq(MOCK_COUNTRY_CODE), eq(MOCK_PHONE_NUMBER_WITH_AREA_CODE)))
                .thenThrow(new RuntimeException("Something unexpected happened"));

        try {
            this.authenticationService.startLoginByMobileID(requestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            assertThat(e, instanceOf(RuntimeException.class));
            assertThat(e.getMessage(), containsString("Something unexpected happened"));
            this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, "Something unexpected happened");
        }
    }

    @Test
    public void startLoginByMobileIDSucceeds() {
        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", createCredentialWithIdAndNumber()
        );

        final MobileIDSession mobileIDSession = createMobileIDSession();
        Mockito.when(authenticatorMock.startLogin(MOCK_PERSONAL_CODE, configurationProvider.getCountryCode(), MOCK_PHONE_NUMBER_WITH_AREA_CODE))
                .thenReturn(mobileIDSession);

        Event event = this.authenticationService.startLoginByMobileID(requestContext);
        assertEquals("success", event.getId());

        assertEquals(MOCK_VERIFICATION_CODE, requestContext.getFlowScope().get(Constants.MOBILE_ID_VERIFICATION_CODE));
        MobileIDSOAPSession authSession = (MobileIDSOAPSession) requestContext.getFlowScope().get(Constants.MOBILE_ID_AUTHENTICATION_SESSION);
        assertEquals(mobileIDSession.challenge, authSession.getVerificationCode());
        assertEquals(String.valueOf(mobileIDSession.sessCode), authSession.getSessionId());
        assertEquals(mobileIDSession, authSession.getWrappedSession());
        assertEquals(0, requestContext.getFlowScope().get(Constants.AUTH_COUNT));

        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    @Test
    public void checkLoginForMobileIDSucceedsAsOutstanding() {
        final RequestContext requestContext = this.getMockRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenReturn(false);

        Event event = this.authenticationService.checkLoginForMobileID(requestContext);
        assertEquals("outstanding", event.getId());

        assertEquals(new Integer(1), requestContext.getFlowScope().getInteger(Constants.AUTH_COUNT));
        SimpleTestAppender.verifyNoLogEventsExist(Matchers.any(String.class));
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenUserError() {

        for (AuthenticationException.Code code : Arrays.asList(EXPIRED_TRANSACTION,
                USER_CANCEL, MID_NOT_READY, PHONE_ABSENT, SENDING_ERROR, SIM_ERROR)) {

            RequestContext requestContext = mockIsLoginComplete(code);

            try {
                authenticationService.checkLoginForMobileID(requestContext);
                Assert.fail("Should not reach this!");
            } catch (Exception e) {
                assertThat(e, instanceOf(UserAuthenticationFailedException.class));
                assertThat(e.getMessage(), containsString("User authentication failed! DDS GetMobileAuthenticateStatus returned an error (code: " + code + ")"));
                assertEquals(String.format("message.mid.%s", code.name().toLowerCase().replace("_", "")),
                        (((UserAuthenticationFailedException)e).getErrorMessageKey()));
                this.verifyLogContentsOnFailure(code.name().toUpperCase());
            }
        }
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenDdsInternalError() {

        for (AuthenticationException.Code code : Arrays.asList(INTERNAL_ERROR)) {

            RequestContext requestContext = mockIsLoginComplete(code);

            try {
                authenticationService.checkLoginForMobileID(requestContext);
                Assert.fail("Should not reach this!");
            } catch (Exception e) {
                assertThat(e, instanceOf(ExternalServiceHasFailedException.class));
                assertThat(e.getMessage(), containsString("Technical problems with DDS! DDS GetMobileAuthenticateStatus returned an error (code: " + code.name() + ")"));
                this.verifyLogContentsOnFailure(code.name().toUpperCase());
            }
        }
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenServiceUnavailable() {
        SimpleTestAppender.events.clear();
        RequestContext requestContext = this.getMockRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenThrow(
                new AuthenticationException(SERVICE_ERROR, "timout!", new SocketTimeoutException("timout"))
        );

        try {
            authenticationService.checkLoginForMobileID(requestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            assertThat(e, instanceOf(ExternalServiceHasFailedException.class));
            assertThat(e.getMessage(), containsString("Technical problems with DDS! DDS GetMobileAuthenticateStatus returned an error (code: " + SERVICE_ERROR + ")"));
            this.verifyLogContentsOnFailure(SERVICE_ERROR.name().toUpperCase());
        }
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenUnexpectedDdsError() {

        for (AuthenticationException.Code code : Arrays.asList(SERVICE_ERROR)) {

            RequestContext requestContext = mockIsLoginComplete(code);

            try {
                authenticationService.checkLoginForMobileID(requestContext);
                Assert.fail("Should not reach this!");
            } catch (Exception e) {
                assertThat(e, instanceOf(IllegalStateException.class));
                assertThat(e.getMessage(), containsString("Unexpected error returned by DDS GetMobileAuthenticateStatus (code: " + code + ")"));
                this.verifyLogContentsOnFailure(code.name().toUpperCase());
            }
        }
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenUnexpectedError() {

        for (AuthenticationException.Code code : Arrays.asList(INTERNAL_ERROR)) {

            SimpleTestAppender.events.clear();
            RequestContext requestContext = this.getMockRequestContext(null);
            final MobileIDSession mobileIDSession = createMobileIDSession();

            fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
            Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenThrow(
                    new RuntimeException("Unexpected error")
            );

            try {
                authenticationService.checkLoginForMobileID(requestContext);
                Assert.fail("Should not reach this!");
            } catch (Exception e) {
                assertThat(e, instanceOf(RuntimeException.class));
                assertThat(e.getMessage(), containsString("Unexpected error"));
                this.verifyLogContentsOnFailure("Unexpected error");
            }
        }
    }

    @Test
    public void checkLoginForMobileIDSucceeds() {
        RequestContext requestContext = this.getMockRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenReturn(true);

        Event event = this.authenticationService.checkLoginForMobileID(requestContext);
        assertEquals("success", event.getId());

        TaraCredential credential = (TaraCredential) requestContext.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        this.validateUserCredential(credential);

        this.verifyLogContents(StatisticsOperation.SUCCESSFUL_AUTH);
    }

    private PreAuthenticationCredential createCredentialWithIdAndNumber() {
        PreAuthenticationCredential taraCredential = new PreAuthenticationCredential();
        taraCredential.setPrincipalCode(MOCK_PERSONAL_CODE);
        taraCredential.setMobileNumber(MOCK_PHONE_NUMBER);
        taraCredential.setCountry(MOCK_COUNTRY_CODE);
        return taraCredential;
    }

    private MobileIDSession createMobileIDSession() {
        return new MobileIDSession(
                MOCK_SESSION_CODE,
                MOCK_VERIFICATION_CODE,
                MOCK_FIRST_NAME,
                MOCK_LAST_NAME,
                MOCK_PERSONAL_CODE
        );
    }

    private void fillRequestContextFlowScope(RequestContext requestContext, MobileIDSession mobileIDSession, int authCount) {
        MobileIDSOAPSession sessionWrapper = MobileIDSOAPSession.builder().wrappedSession(mobileIDSession).build();
        requestContext.getFlowScope().put(Constants.MOBILE_ID_VERIFICATION_CODE, sessionWrapper.getVerificationCode());
        requestContext.getFlowScope().put(Constants.MOBILE_ID_AUTHENTICATION_SESSION, sessionWrapper);
        requestContext.getFlowScope().put(Constants.AUTH_COUNT, authCount);
    }

    private void validateUserCredential(TaraCredential credential) {
        Assert.assertNotNull(credential);

        assertEquals(AuthenticationType.MobileID, credential.getType());
        assertEquals("EE" + MOCK_PERSONAL_CODE, credential.getId());
        assertEquals(MOCK_FIRST_NAME, credential.getFirstName());
        assertEquals(MOCK_LAST_NAME, credential.getLastName());
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

    private void verifyLogContentsOnFailure(String errorMessage) {
        SimpleTestAppender.verifyLogEventsExistInOrder(
                Matchers.containsString(String.format(";openIdDemo;%s;%s;%s", AuthenticationType.MobileID, StatisticsOperation.ERROR, errorMessage))
        );
    }

    private void verifyStartLoginError(AuthenticationException.Code errorCode, String expectedErrorMessage, String expectedErrorKey, Class<? extends TaraAuthenticationException> expectedException) {
        SimpleTestAppender.events.clear();
        RequestContext requestContext = this.getMockRequestContext(null);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", createCredentialWithIdAndNumber()
        );

        Mockito.when(authenticatorMock.startLogin(eq(MOCK_PERSONAL_CODE), eq(MOCK_COUNTRY_CODE), eq(MOCK_PHONE_NUMBER_WITH_AREA_CODE)))
                .thenThrow(new AuthenticationException(errorCode));

        try {
            this.authenticationService.startLoginByMobileID(requestContext);
            Assert.fail("Should not reach this!");
        } catch (TaraAuthenticationException e) {
            assertThat(e, instanceOf(expectedException));
            assertThat(e.getMessage(), containsString(expectedErrorMessage));
            assertEquals(expectedErrorKey, e.getErrorMessageKey());
            this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, errorCode.name().toUpperCase());
        }
    }

    private RequestContext mockIsLoginComplete(AuthenticationException.Code code) {
        SimpleTestAppender.events.clear();
        RequestContext requestContext = this.getMockRequestContext(null);
        final MobileIDSession mobileIDSession = createMobileIDSession();

        fillRequestContextFlowScope(requestContext, mobileIDSession, 0);
        Mockito.when(authenticatorMock.isLoginComplete(mobileIDSession)).thenThrow(
                new AuthenticationException(code)
        );
        return requestContext;
    }
}
