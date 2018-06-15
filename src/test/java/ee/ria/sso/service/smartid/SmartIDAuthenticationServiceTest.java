package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.TaraCredentialsException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.exception.RequestForbiddenException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.test.MockRequestContext;

import javax.ws.rs.ClientErrorException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

import static ee.ria.sso.service.smartid.SmartIDMockData.*;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestSmartIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class SmartIDAuthenticationServiceTest {

    @Mock
    private StatisticsHandler statisticsHandler;

    @Mock
    private SmartIDClient smartIdClient;

    @Mock
    private TaraResourceBundleMessageSource messageSource;

    @Mock
    private SmartIDAuthenticationValidatorWrapper authResponseValidator;

    @Autowired
    private SmartIDConfigurationProvider confProvider;

    private SmartIDAuthenticationService authenticationService;

    @Captor
    private ArgumentCaptor<AuthenticationHash> authHashArgumentCaptor;

    @Captor
    private ArgumentCaptor<String> errorMessageKeyCaptor;

    @Before
    public void init() {
        authenticationService = new SmartIDAuthenticationService(
                messageSource,
                statisticsHandler,
                smartIdClient,
                confProvider,
                authResponseValidator
        );
    }

    @Test
    public void authenticationSessionInitiationSuccessful() {
        TaraCredential credential = mockCredential();
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);

        String sessionId = UUID.randomUUID().toString();
        mockSubjectAuthenticationCall(credential, sessionId);

        Event event = authenticationService.initSmartIdAuthenticationSession(requestContext);

        assertEventSuccessful(event);
        assertVerificationCodeInFlowContext(requestContext);
        assertVerificationCodeFromSameHashAsInAuthenticationRequest(requestContext);
        assertAuthSessionInFlowContext(requestContext, sessionId, 0);
        assertAuthStartStatisticsCollected(requestContext);
    }

    @Test
    public void authenticationSessionInitiation_userAccountNotFoundException() {
        initAuthSessionAndExpectSmartIdClientException(
                new UserAccountNotFoundException(), SmartIDErrorMessage.USER_ACCOUNT_NOT_FOUND);
    }

    @Test
    public void authenticationSessionInitiation_requestForbiddenException() {
        initAuthSessionAndExpectSmartIdClientException(
                new RequestForbiddenException(), SmartIDErrorMessage.REQUEST_FORBIDDEN);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException471() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 471", 471), SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException472() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 472", 472), SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException480() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 480", 480), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException580() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 580", 400), SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE);
    }

    @Test
    public void authenticationSessionInitiation_unhandledSmartIdClientException() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("UNHANDLED", 400), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void authenticationSessionInitiation_unexpectedException() {
        initAuthSessionAndExpectSmartIdClientException(
                new IllegalStateException("UNKNOWN RUNTIME EXCEPTION"), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void authenticationSessionInitiation_authHash256_Successful() {
        confProvider.setAuthenticationHashType(HashType.SHA256);
        TaraCredential credential = mockCredential();
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);

        String sessionId = UUID.randomUUID().toString();
        mockSubjectAuthenticationCall(credential, sessionId);

        Event event = authenticationService.initSmartIdAuthenticationSession(requestContext);

        assertEventSuccessful(event);
        assertVerificationCodeInFlowContext(requestContext);
        assertVerificationCodeFromSameHashAsInAuthenticationRequest(requestContext);
        assertAuthSessionInFlowContext(requestContext, sessionId, 0);
        assertAuthStartStatisticsCollected(requestContext);

        assertEquals(HashType.SHA256, authHashArgumentCaptor.getValue().getHashType());
    }

    @Test
    public void authenticationSessionInitiation_personIdentifierInvalidFormat() {
        List<TaraCredential> invalidCredentials = Arrays.asList(
                mockCredential(StringUtils.repeat('1', 10)),
                mockCredential(StringUtils.repeat('1', 12)),
                mockCredential(StringUtils.repeat('1', 1)),
                mockCredential("4710101003a"),
                mockCredential("4710101003+"),
                mockCredential("4710101003#")
        );

        invalidCredentials.forEach(invalidCredential -> {
            MockRequestContext requestContext = mockAuthInitRequestContext(invalidCredential);

            assertExceptionThrownDuringAuthSessionInit(
                    requestContext,
                    TaraCredentialsException.class,
                    SmartIDErrorMessage.INVALID_PERSON_IDENTIFIER
            );
        });
    }

    @Test
    public void authenticationSessionInitiation_personIdentifierMissing() {
        TaraCredential credential = mockCredential();
        credential.setPrincipalCode("");
        credential.setCountry("EE");
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);

        assertExceptionThrownDuringAuthSessionInit(
                requestContext,
                TaraCredentialsException.class,
                SmartIDErrorMessage.PERSON_IDENTIFIER_MISSING
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionStateRunning() {
        String sessionId = UUID.randomUUID().toString();
        mockAuthSessionStatusCheckCall(sessionId, mockRunningSessionStatus());

        int statusCheckCount = 2;
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, statusCheckCount);
        Event event = authenticationService.checkSmartIdAuthenticationSessionStatus(requestContext);

        assertEventOutstanding(event);
        assertVerificationCodeInFlowContext(requestContext);
        assertAuthSessionInFlowContext(requestContext, sessionId, statusCheckCount + 1);
    }

    @Test
    public void getAuthenticationSessionStatus_sessionStateCompleteAndValid() {
        String sessionId = UUID.randomUUID().toString();
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        mockAuthSessionStatusCheckCall(sessionId, sessionStatus);

        SmartIdAuthenticationResult authenticationResult= mockAuthenticationResult(SmartIDMockData.VALID_EE_PERSON_IDENTIFIER, "EE");
        mockAuthSessionValidation(authenticationResult);

        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);
        Event event = authenticationService.checkSmartIdAuthenticationSessionStatus(requestContext);

        assertEventSuccessful(event);
        assertSuccessfulAuthStatisticsCollected(requestContext);
        assertCertPersonCredentialsInFlowContext(requestContext, authenticationResult.getAuthenticationIdentity());
    }

    @Test
    public void getAuthenticationSessionStatus_sessionNotFoundException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new SessionNotFoundException(), SmartIDErrorMessage.SESSION_NOT_FOUND);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException471() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 471", 471), SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException472() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 472", 472), SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException480() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 480", 480), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException580() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 580", 400), SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE);
    }

    @Test
    public void getAuthenticationSessionStatus_unhandledSmartIdClientException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("UNHANDLED", 400), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void getAuthenticationSessionStatus_unexpectedException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new IllegalStateException("UNKNOWN RUNTIME EXCEPTION"), SmartIDErrorMessage.GENERAL);
    }

    @Test
    public void getAuthenticationSessionStatus_sessionValidationException() {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.USER_REFUSED);
        mockAuthSessionStatusCheckCall(sessionId, sessionStatus);

        SessionValidationException expectedException = new SessionValidationException("User refused", SmartIDErrorMessage.USER_REFUSED_AUTHENTICATION);
        when(authResponseValidator.validateAuthenticationResponse(sessionStatus, authHash))
                .thenThrow(expectedException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                expectedException.getClass(),
                expectedException.getErrorMessageKey(),
                expectedException.getMessage()
        );
    }

    @Test
    public void getAuthenticationSessionStatus_invalidStateExceptionDuringSessionValidation() {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        mockAuthSessionStatusCheckCall(sessionId, sessionStatus);

        IllegalStateException expectedException = new IllegalStateException("Unknown end result");
        when(authResponseValidator.validateAuthenticationResponse(sessionStatus, authHash))
                .thenThrow(expectedException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                expectedException.getClass(),
                SmartIDErrorMessage.GENERAL,
                expectedException.getMessage()
        );
    }

    private void assertErrorMessage(String expectedErrorMessageKey) {
        verify(messageSource, times(1)).getMessage(any());
        verify(messageSource).getMessage(errorMessageKeyCaptor.capture());
        reset(messageSource);
        assertEquals(expectedErrorMessageKey, errorMessageKeyCaptor.getValue());
    }

    private void initAuthSessionAndExpectSmartIdClientException(Exception mockException, String expectedErrorMessageKey) {
        TaraCredential credential = mockCredential();
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);
        mockSubjectAuthenticationCallException(credential, mockException);

        assertExceptionThrownDuringAuthSessionInit(
                requestContext,
                mockException.getClass(),
                expectedErrorMessageKey
        );
    }

    private void assertExceptionThrownDuringAuthSessionInit(MockRequestContext requestContext, Class<? extends Exception> exceptionType, String errorMessageKey) {
        expectException(
                () -> authenticationService.initSmartIdAuthenticationSession(requestContext),
                requestContext,
                exceptionType,
                errorMessageKey);

        assertAuthStartStatisticsCollected(requestContext);
    }

    private void getAuthSessionStatusAndExpectSmartIdClientException(Exception mockException, String expectedErrorMessageKey) {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        mockAuthSessionStatusCheckException(sessionId, mockException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                mockException.getClass(),
                expectedErrorMessageKey,
                null
        );
    }

    private void assertExceptionThrownDuringAuthSessionStatusCheck(
            MockRequestContext requestContext,
            Class<? extends Exception> exceptionType,
            String expectedErrorMessageKey,
            String exceptionMessage) {

        expectException(
                () -> authenticationService.checkSmartIdAuthenticationSessionStatus(requestContext),
                requestContext,
                exceptionType,
                expectedErrorMessageKey,
                exceptionMessage);
    }

    private void expectException(Callable processToThrowException, MockRequestContext requestContext, Class<? extends Exception> exceptionType, String errorMessageKey) {
        expectException(processToThrowException, requestContext, exceptionType, errorMessageKey, null);
    }

    private void expectException(
            Callable processToThrowException,
            MockRequestContext requestContext,
            Class<? extends Exception> exceptionType,
            String errorMessageKey,
            String exceptionMessage) {

        try {
            processToThrowException.call();
        } catch (Exception e) {
            if (!(e instanceof TaraAuthenticationException)) {
                fail("Invalid exception caught! Is <" + e.getClass() + ">, but expected to be <" + TaraAuthenticationException.class + ">");
            }
            Throwable cause = e.getCause();
            if (!exceptionType.isInstance(cause)) {
                fail("Invalid inner exception caught! Is <" + cause.getClass() + ">, but expected to be <" + exceptionType + ">");
            }

            if (exceptionMessage != null) {
                assertEquals(exceptionMessage, cause.getMessage());
            }

            assertContextCleared(requestContext);
            assertErrorStatisticsCollected(requestContext, cause.getMessage());
            assertErrorMessage(errorMessageKey);
        }
    }

    private void assertEventSuccessful(Event event) {
        assertEvent(event, SmartIDAuthenticationService.EVENT_SUCCESSFUL);
    }

    private void assertEventOutstanding(Event event) {
        assertEvent(event, SmartIDAuthenticationService.EVENT_OUTSTANDING);
    }

    private void assertEvent(Event event, String expectedId) {
        assertEquals(expectedId, event.getId());
        assertTrue(event.getSource() instanceof SmartIDAuthenticationService);
    }

    private void assertContextCleared(MockRequestContext requestContext) {
        assertTrue(requestContext.getFlowScope().isEmpty());
    }

    private void assertAuthSessionInFlowContext(MockRequestContext requestContext, String sessionId, int sessionStatusCheckCount) {
        AuthenticationSession authSession =
                requestContext.getFlowScope().get(Constants.SMART_ID_AUTHENTICATION_SESSION, AuthenticationSession.class);
        assertNotNull(authSession);
        assertEquals(sessionId, authSession.getSessionId());
        assertEquals(sessionStatusCheckCount, authSession.getStatusCheckCount());
    }

    private void assertVerificationCodeInFlowContext(MockRequestContext requestContext) {
        String verificationCode = requestContext.getFlowScope().get(Constants.SMART_ID_VERIFICATION_CODE, String.class);
        assertNotNull(verificationCode);
        assertSame(4, verificationCode.length());
    }

    private void assertVerificationCodeFromSameHashAsInAuthenticationRequest(MockRequestContext requestContext) {
        String verificationCodeFromContext = requestContext.getFlowScope().get(Constants.SMART_ID_VERIFICATION_CODE, String.class);
        verify(smartIdClient).authenticateSubject(any(), any(), authHashArgumentCaptor.capture());
        String verificationCodeFromRequestHash = authHashArgumentCaptor.getValue().calculateVerificationCode();
        assertEquals(verificationCodeFromContext, verificationCodeFromRequestHash);
    }

    private void assertCertPersonCredentialsInFlowContext(MockRequestContext requestContext, AuthenticationIdentity authIdentity) {
        TaraCredential credential = requestContext.getFlowExecutionContext().getActiveSession().getScope().get(Constants.CREDENTIAL, TaraCredential.class);
        assertEquals(authIdentity.getCountry() + authIdentity.getIdentityCode(), credential.getPrincipalCode());
        assertEquals(authIdentity.getGivenName(), credential.getFirstName());
        assertEquals(authIdentity.getSurName(), credential.getLastName());
    }

    private void assertAuthStartStatisticsCollected(MockRequestContext requestContext) {
        verify(statisticsHandler, times(1)).collect(
                any(),
                eq(requestContext),
                eq(AuthenticationType.SmartID),
                eq(StatisticsOperation.START_AUTH));
    }

    private void assertSuccessfulAuthStatisticsCollected(MockRequestContext requestContext) {
        verify(statisticsHandler, times(1)).collect(
                any(),
                eq(requestContext),
                eq(AuthenticationType.SmartID),
                eq(StatisticsOperation.SUCCESSFUL_AUTH));
    }

    private void assertErrorStatisticsCollected(MockRequestContext requestContext, String exceptionMessage) {
        verify(statisticsHandler, times(1)).collect(
                any(),
                eq(requestContext),
                eq(AuthenticationType.SmartID),
                eq(StatisticsOperation.ERROR),
                eq(exceptionMessage));
    }

    private void mockSubjectAuthenticationCall(TaraCredential credential, String sessionId) {
        AuthenticationSessionResponse mockResponse = new AuthenticationSessionResponse();
        mockResponse.setSessionId(sessionId);
        when(smartIdClient.authenticateSubject(
                eq(credential.getCountry()),
                eq(credential.getPrincipalCode()),
                any()))
                .thenReturn(mockResponse);
    }

    private void mockSubjectAuthenticationCallException(TaraCredential credential, Exception exception) {
        when(smartIdClient.authenticateSubject(
                eq(credential.getCountry()),
                eq(credential.getPrincipalCode()),
                any()))
                .thenThrow(exception);
    }

    private void mockAuthSessionStatusCheckCall(String sessionId, SessionStatus sessionStatus) {
        when(smartIdClient.getSessionStatus(sessionId)).thenReturn(sessionStatus);
    }

    private void mockAuthSessionStatusCheckException(String sessionId, Exception exception) {
        when(smartIdClient.getSessionStatus(sessionId)).thenThrow(exception);
    }

    private void mockAuthSessionValidation(SmartIdAuthenticationResult authResult) {
        when(authResponseValidator.validateAuthenticationResponse(any(), any())).thenReturn(authResult);
    }

}
