package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.TaraAuthenticationException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecordMatcher;
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
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.test.MockRequestContext;

import javax.ws.rs.ClientErrorException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

import static ee.ria.sso.service.smartid.SmartIDMockData.*;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.*;
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
    private ThymeleafSupport thymeleafSupport;

    @Mock
    private SmartIDAuthenticationValidatorWrapper authResponseValidator;

    @Autowired
    private SmartIDConfigurationProvider confProvider;

    private SmartIDAuthenticationService authenticationService;

    @Captor
    private ArgumentCaptor<SmartIDClient.AuthenticationRequest> authenticationRequestCaptor;

    @Captor
    private ArgumentCaptor<String> errorMessageKeyCaptor;

    @Before
    public void init() {
        authenticationService = new SmartIDAuthenticationService(
                statisticsHandler,
                smartIdClient,
                confProvider,
                authResponseValidator
        );
    }

    @Test
    public void authenticationSessionInitiationSuccessful() {
        PreAuthenticationCredential credential = mockCredential();
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);

        String sessionId = UUID.randomUUID().toString();
        mockSubjectAuthenticationCall(sessionId);

        Event event = authenticationService.initSmartIdAuthenticationSession(requestContext);

        assertEventSuccessful(event);
        assertVerificationCodeInFlowContext(requestContext);
        assertVerificationCodeFromSameHashAsInAuthenticationRequest(requestContext);
        assertAuthSessionInFlowContext(requestContext, sessionId, 0);
        assertAuthStartStatisticsCollected();
        assertAuthenticationRequestCreation(credential);
    }

    @Test
    public void authenticationSessionInitiation_userAccountNotFoundException() {
        initAuthSessionAndExpectSmartIdClientException(
                new UserAccountNotFoundException(), SmartIDErrorMessage.USER_ACCOUNT_NOT_FOUND, UserAuthenticationFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_requestForbiddenException() {
        initAuthSessionAndExpectSmartIdClientException(
                new RequestForbiddenException(), SmartIDErrorMessage.REQUEST_FORBIDDEN, UserAuthenticationFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException471() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 471", 471), SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT, UserAuthenticationFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException472() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 472", 472), SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE, UserAuthenticationFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException480() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 480", 480), SmartIDErrorMessage.GENERAL, UserAuthenticationFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_smartIdClientException580() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 580", 400), SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE, ExternalServiceHasFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_unhandledSmartIdClientException() {
        initAuthSessionAndExpectSmartIdClientException(
                new ClientErrorException("UNHANDLED", 400), SmartIDErrorMessage.GENERAL, ExternalServiceHasFailedException.class);
    }

    @Test
    public void authenticationSessionInitiation_unexpectedException() {
        initAuthSessionAndExpectSmartIdClientException(
                new IllegalStateException("UNKNOWN RUNTIME EXCEPTION"), SmartIDErrorMessage.GENERAL, IllegalStateException.class);
    }

    @Test
    public void authenticationSessionInitiation_authHash256_Successful() {
        HashType origTestConfHashType = confProvider.getAuthenticationHashType();
        try {
            // Override test conf parameter, must switched back after the test run
            confProvider.setAuthenticationHashType(HashType.SHA256);
            PreAuthenticationCredential credential = mockCredential();
            MockRequestContext requestContext = mockAuthInitRequestContext(credential);

            String sessionId = UUID.randomUUID().toString();
            mockSubjectAuthenticationCall(sessionId);

            Event event = authenticationService.initSmartIdAuthenticationSession(requestContext);

            assertEventSuccessful(event);
            assertVerificationCodeInFlowContext(requestContext);
            assertVerificationCodeFromSameHashAsInAuthenticationRequest(requestContext);
            assertAuthSessionInFlowContext(requestContext, sessionId, 0);
            assertAuthStartStatisticsCollected();

            assertEquals(HashType.SHA256, authenticationRequestCaptor.getValue().getAuthenticationHash().getHashType());
        } finally {
            confProvider.setAuthenticationHashType(origTestConfHashType);
        }
    }

    @Test
    public void authenticationSessionInitiation_personIdentifierInvalidFormat() {
        List<PreAuthenticationCredential> invalidCredentials = Arrays.asList(
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
                    new UserAuthenticationFailedException(SmartIDErrorMessage.INVALID_PERSON_IDENTIFIER, invalidCredential.getPrincipalCode()),
                    SmartIDErrorMessage.INVALID_PERSON_IDENTIFIER, UserAuthenticationFailedException.class
            );
            Mockito.reset(statisticsHandler);
        });
    }

    @Test
    public void authenticationSessionInitiation_personIdentifierMissing() {
        PreAuthenticationCredential credential = mockCredential();
        credential.setPrincipalCode("");
        credential.setCountry("EE");
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);

        assertExceptionThrownDuringAuthSessionInit(
                requestContext,
                new UserAuthenticationFailedException(SmartIDErrorMessage.PERSON_IDENTIFIER_MISSING, credential.getPrincipalCode()),
                SmartIDErrorMessage.PERSON_IDENTIFIER_MISSING, UserAuthenticationFailedException.class
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
        assertSuccessfulAuthStatisticsCollected();
        assertCertPersonCredentialsInFlowContext(requestContext, authenticationResult.getAuthenticationIdentity());
    }

    @Test
    public void getAuthenticationSessionStatus_sessionNotFoundException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new SessionNotFoundException(), SmartIDErrorMessage.SESSION_NOT_FOUND, UserAuthenticationFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException471() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 471", 471), SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT, UserAuthenticationFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException472() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 472", 472), SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE, UserAuthenticationFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException480() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 480", 480), SmartIDErrorMessage.GENERAL, UserAuthenticationFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_smartIdClientException580() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("HTTP 580", 400), SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE, ExternalServiceHasFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_unhandledSmartIdClientException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new ClientErrorException("UNHANDLED", 400), SmartIDErrorMessage.GENERAL, ExternalServiceHasFailedException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_unexpectedException() {
        getAuthSessionStatusAndExpectSmartIdClientException(
                new IllegalStateException("UNKNOWN RUNTIME EXCEPTION"), SmartIDErrorMessage.GENERAL, IllegalStateException.class);
    }

    @Test
    public void getAuthenticationSessionStatus_sessionValidationException() {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.USER_REFUSED);
        mockAuthSessionStatusCheckCall(sessionId, sessionStatus);

        SessionValidationException expectedException = new SessionValidationException("User refused", SmartIDErrorMessage.USER_REFUSED_AUTHENTICATION);
        when(authResponseValidator.validateAuthenticationResponse(sessionStatus, authHash, CertificateLevel.QUALIFIED))
                .thenThrow(expectedException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                expectedException,
                expectedException.getErrorMessageKey(),
                expectedException.getMessage(), UserAuthenticationFailedException.class
        );
    }

    @Test
    public void getAuthenticationSessionStatus_invalidStateExceptionDuringSessionValidation() {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        mockAuthSessionStatusCheckCall(sessionId, sessionStatus);

        IllegalStateException mockException = new IllegalStateException("Unknown end result");
        when(authResponseValidator.validateAuthenticationResponse(sessionStatus, authHash, CertificateLevel.QUALIFIED))
                .thenThrow(mockException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                mockException,
                SmartIDErrorMessage.GENERAL,
                mockException.getMessage(), IllegalStateException.class
        );
    }

    private void initAuthSessionAndExpectSmartIdClientException(Exception mockException, String expectedErrorMessageKey, Class<? extends Exception> expectedException) {
        PreAuthenticationCredential credential = mockCredential();
        MockRequestContext requestContext = mockAuthInitRequestContext(credential);
        mockSubjectAuthenticationCallException(mockException);

        assertExceptionThrownDuringAuthSessionInit(
                requestContext,
                mockException,
                expectedErrorMessageKey, expectedException
        );

        assertAuthenticationRequestCreation(credential);
    }

    private void assertExceptionThrownDuringAuthSessionInit(MockRequestContext requestContext, Exception mockException, String errorMessageKey, Class<? extends Exception> expectedException) {
        expectException(
                () -> authenticationService.initSmartIdAuthenticationSession(requestContext),
                requestContext,
                mockException,
                errorMessageKey, expectedException);

        assertAuthStartStatisticsCollected();
    }

    private void getAuthSessionStatusAndExpectSmartIdClientException(Exception mockException, String expectedErrorMessageKey, Class<? extends Exception> expectedException) {
        String sessionId = UUID.randomUUID().toString();
        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        MockRequestContext requestContext = mockSessionStatusRequestContext(authHash, sessionId, 0);

        mockAuthSessionStatusCheckException(sessionId, mockException);

        assertExceptionThrownDuringAuthSessionStatusCheck(
                requestContext,
                mockException,
                expectedErrorMessageKey,
                mockException.getMessage(), expectedException
        );
    }

    private void assertExceptionThrownDuringAuthSessionStatusCheck(
            MockRequestContext requestContext,
            Exception mockException,
            String expectedErrorMessageKey,
            String exceptionMessage, Class<? extends Exception> expectedException) {

        expectException(
                () -> authenticationService.checkSmartIdAuthenticationSessionStatus(requestContext),
                expectedErrorMessageKey,
                exceptionMessage, expectedException);
    }

    private void expectException(Callable processToThrowException, MockRequestContext requestContext, Exception mockException, String errorMessageKey, Class<? extends Exception> expectedException) {
        expectException(processToThrowException, errorMessageKey, mockException.getMessage(), expectedException);
    }

    private void expectException(
            Callable processToThrowException,
            String errorMessageKey,
            String exceptionMessage, Class<? extends Exception> expectedException) {

        try {
            processToThrowException.call();
        } catch (Exception e) {
            assertThat(e, instanceOf(expectedException));
            assertEquals(exceptionMessage, e.getMessage());
            assertErrorStatisticsCollected(e.getMessage());
            if (e instanceof TaraAuthenticationException) {
                assertEquals(errorMessageKey,((TaraAuthenticationException) e).getErrorMessageKey());
            }
        }
    }

    private void assertEventSuccessful(Event event) {
        assertEvent(event, CasWebflowConstants.TRANSITION_ID_SUCCESS);
    }

    private void assertEventOutstanding(Event event) {
        assertEvent(event, Constants.EVENT_OUTSTANDING);
    }

    private void assertEvent(Event event, String expectedId) {
        assertEquals(expectedId, event.getId());
        assertTrue(event.getSource() instanceof SmartIDAuthenticationService);
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
        String fromContext = requestContext.getFlowScope().get(Constants.SMART_ID_VERIFICATION_CODE, String.class);
        verify(smartIdClient, times(1)).authenticateSubject(authenticationRequestCaptor.capture());
        String fromRequestHash = authenticationRequestCaptor.getValue().getAuthenticationHash().calculateVerificationCode();
        assertEquals(fromContext, fromRequestHash);
    }

    private void assertCertPersonCredentialsInFlowContext(MockRequestContext requestContext, AuthenticationIdentity authIdentity) {
        TaraCredential credential = requestContext.getFlowExecutionContext().getActiveSession().getScope().get(CasWebflowConstants.VAR_ID_CREDENTIAL, TaraCredential.class);
        assertEquals(authIdentity.getCountry() + authIdentity.getIdentityCode(), credential.getPrincipalCode());
        assertEquals(authIdentity.getGivenName(), credential.getFirstName());
        assertEquals(authIdentity.getSurName(), credential.getLastName());
    }

    private void assertAuthStartStatisticsCollected() {
        verify(statisticsHandler, times(1)).collect(argThat(
                new StatisticsRecordMatcher(
                        Matchers.any(LocalDateTime.class),
                        Matchers.equalTo("clientId"),
                        Matchers.equalTo(AuthenticationType.SmartID),
                        Matchers.equalTo(StatisticsOperation.START_AUTH),
                        Matchers.nullValue(String.class),
                        Matchers.nullValue(String.class)
                )
        ));
    }

    private void assertSuccessfulAuthStatisticsCollected() {
        verify(statisticsHandler, times(1)).collect(argThat(
                new StatisticsRecordMatcher(
                        Matchers.any(LocalDateTime.class),
                        Matchers.equalTo("clientId"),
                        Matchers.equalTo(AuthenticationType.SmartID),
                        Matchers.equalTo(StatisticsOperation.SUCCESSFUL_AUTH),
                        Matchers.nullValue(String.class),
                        Matchers.nullValue(String.class)
                )
        ));
    }

    private void assertErrorStatisticsCollected(String exceptionMessage) {
        verify(statisticsHandler, times(1)).collect(argThat(
                new StatisticsRecordMatcher(
                        Matchers.any(LocalDateTime.class),
                        Matchers.equalTo("clientId"),
                        Matchers.equalTo(AuthenticationType.SmartID),
                        Matchers.equalTo(StatisticsOperation.ERROR),
                        exceptionMessage == null ? Matchers.isEmptyOrNullString() : Matchers.equalTo(exceptionMessage),
                        Matchers.nullValue(String.class)
                )
        ));
    }

    private void mockSubjectAuthenticationCall(String sessionId) {
        AuthenticationSessionResponse mockResponse = new AuthenticationSessionResponse();
        mockResponse.setSessionID(sessionId);
        when(smartIdClient.authenticateSubject(authenticationRequestCaptor.capture()))
                .thenReturn(mockResponse);
    }

    private void mockSubjectAuthenticationCallException(Exception exception) {
        when(smartIdClient.authenticateSubject(authenticationRequestCaptor.capture()))
                .thenThrow(exception);
    }

    private void assertAuthenticationRequestCreation(PreAuthenticationCredential credential) {
        verify(smartIdClient, times(1)).authenticateSubject(authenticationRequestCaptor.capture());
        SmartIDClient.AuthenticationRequest authRequest = authenticationRequestCaptor.getValue();
        assertEquals(credential.getCountry(), authRequest.getPersonCountry());
        assertEquals(credential.getPrincipalCode(), authRequest.getPersonIdentifier());
        assertEquals(CertificateLevel.QUALIFIED, authRequest.getCertificateLevel());
    }

    private void mockAuthSessionStatusCheckCall(String sessionId, SessionStatus sessionStatus) {
        when(smartIdClient.getSessionStatus(sessionId)).thenReturn(sessionStatus);
    }

    private void mockAuthSessionStatusCheckException(String sessionId, Exception exception) {
        when(smartIdClient.getSessionStatus(sessionId)).thenThrow(exception);
    }

    private void mockAuthSessionValidation(SmartIdAuthenticationResult authResult) {
        when(authResponseValidator.validateAuthenticationResponse(any(), any(), any())).thenReturn(authResult);
    }

}
