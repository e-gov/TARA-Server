package ee.ria.sso.service.mobileid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.config.mobileid.TestMobileIDConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.mobileid.rest.MobileIDErrorMessage;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTSession;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTSessionStatus;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import ee.sk.mid.MidClient;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.hamcrest.Matchers;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import static ee.ria.sso.Constants.MOBILE_ID_AUTHENTICATION_SESSION;
import static ee.ria.sso.Constants.MOBILE_ID_VERIFICATION_CODE;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "mobile-id.use-dds-service=true" })
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class MobileIDAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    private static final String MOCK_SESSION_CODE = "1123456789";
    private static final String MOCK_VERIFICATION_CODE = "mockVerificationCode";
    private static final String MOCK_FIRST_NAME = "MARY ÄNN";
    private static final String MOCK_LAST_NAME = "O’CONNEŽ-ŠUSLIK";
    private static final String MOCK_PERSONAL_CODE = "60001019906";
    private static final String MOCK_PHONE_NUMBER = "2123456789";
    private static final String MOCK_AREA_CODE = "+372";
    private static final String MOCK_PHONE_NUMBER_WITH_AREA_CODE = MOCK_AREA_CODE + MOCK_PHONE_NUMBER;
    private static final String MOCK_COUNTRY_CODE = "EE";

    @Mock
    private MobileIDConfigurationProvider configurationProvider;

    @Autowired
    private StatisticsHandler statisticsHandler;

    private MobileIDAuthenticationService authenticationService;

    @Mock
    private MobileIDAuthenticationClient authenticationClient;

    @Mock
    private MidClient client;

    @Before
    public void setUp() {
        authenticationService = new MobileIDAuthenticationService(statisticsHandler, configurationProvider, authenticationClient);
        when(configurationProvider.getCountryCode()).thenReturn(MOCK_COUNTRY_CODE);
        when(configurationProvider.getAreaCode()).thenReturn(MOCK_AREA_CODE);
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenPreAuthCredentialNotPresent() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("PreAuthenticationCredential is missing!");

        authenticationService.startLoginByMobileID(this.getMockRequestContext(null));
        fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileNumberNotPresent() {
        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided invalid mobileNumber: <null>");

        PreAuthenticationCredential credential = createPreAuthenticationCredentialWithIdAndNumber();
        credential.setMobileNumber(null);

        authenticationService.startLoginByMobileID(createPreAuthenticationRequestContext(credential));
        fail("Should not reach this!");
    }


    @Test
    public void startLoginByMobileIDShouldFailWhenNoPrincipalCodePresent() {
        expectedEx.expect(UserAuthenticationFailedException.class);
        expectedEx.expectMessage("User provided invalid identityCode: <null>");

        PreAuthenticationCredential credential = createPreAuthenticationCredentialWithIdAndNumber();
        credential.setPrincipalCode(null);

        authenticationService.startLoginByMobileID(createPreAuthenticationRequestContext(credential));
        fail("Should not reach this!");
    }

    @Test
    public void startLoginByMobileIDSucceeds() {
        RequestContext mockRequestContext = createPreAuthenticationRequestContext(createPreAuthenticationCredentialWithIdAndNumber());

        final MobileIDSession mockMobileIDSession = createMockMobileIDSession();
        when(authenticationClient.initAuthentication(MOCK_PERSONAL_CODE, configurationProvider.getCountryCode(), MOCK_PHONE_NUMBER_WITH_AREA_CODE))
                .thenReturn(mockMobileIDSession);

        Event event = this.authenticationService.startLoginByMobileID(mockRequestContext);

        assertEquals(mockMobileIDSession.getVerificationCode(), getAttrFromFlowScope(mockRequestContext, MOBILE_ID_VERIFICATION_CODE));
        MobileIDRESTSession authSession = (MobileIDRESTSession) getAttrFromFlowScope(mockRequestContext, MOBILE_ID_AUTHENTICATION_SESSION);
        assertEquals(mockMobileIDSession.getVerificationCode(), authSession.getVerificationCode());
        assertEquals(mockMobileIDSession.getSessionId(), authSession.getSessionId());
        assertEquals(0, getAttrFromFlowScope(mockRequestContext, Constants.AUTH_COUNT));
        assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, event.getId());

        this.verifyLogContents(StatisticsOperation.START_AUTH);
    }

    @Test
    public void startLoginByMobileIDShouldFailWhenMobileIDAuthenticatorStartLoginThrowsAnException() {
        RequestContext mockRequestContext = createPreAuthenticationRequestContext(createPreAuthenticationCredentialWithIdAndNumber());

        when (authenticationClient.initAuthentication(
                eq(MOCK_PERSONAL_CODE),
                eq(MOCK_COUNTRY_CODE),
                eq(MOCK_PHONE_NUMBER_WITH_AREA_CODE))
        ).thenThrow(
                new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "error details", new MidInternalErrorException("error cause details"))
        );

        try {
            authenticationService.startLoginByMobileID(mockRequestContext);
            fail("Should not reach this!");
        } catch (Exception e) {
            assertThat(e, instanceOf(ExternalServiceHasFailedException.class));
            assertThat(e.getMessage(), containsString("error details"));
            assertEquals(MobileIDErrorMessage.TECHNICAL, ((ExternalServiceHasFailedException)e).getErrorMessageKey());
            this.verifyLogContentsOnFailure(StatisticsOperation.START_AUTH, "error details");
        }
    }

    @Test
    public void checkLoginForMobileIDSucceedsAsRunning() {

        RequestContext mockRequestContext = getMockRequestContext();
        final MobileIDSession mockMobileIDSession = createMockMobileIDSession();
        fillRequestContextFlowScope(mockRequestContext, mockMobileIDSession, 0);
        MobileIDRESTSessionStatus pollStatus = MobileIDRESTSessionStatus.builder()
                .authenticationComplete(false)
                .wrappedSessionStatus(createMockMidSessionStatus("RUNNING"))
                .build();

        when(authenticationClient.getAuthenticationIdentity(eq(mockMobileIDSession), eq(pollStatus)))
                .thenReturn(AuthenticationIdentity.builder()
                        .identityCode(MOCK_PERSONAL_CODE)
                        .givenName(MOCK_FIRST_NAME)
                        .surname(MOCK_LAST_NAME)
                        .build()
                );
        when(authenticationClient.pollAuthenticationSessionStatus(eq(mockMobileIDSession)))
                .thenReturn(pollStatus);

        Event event = this.authenticationService.checkLoginForMobileID(mockRequestContext);

        assertEquals("Invalid WebFlow event", Constants.EVENT_OUTSTANDING, event.getId());
        assertEquals("Invalid poll count in flow scope", new Integer(1), mockRequestContext.getFlowScope().getInteger(Constants.AUTH_COUNT));
        SimpleTestAppender.verifyNoLogEventsExist(Matchers.any(String.class));
    }

    @Test
    public void checkLoginForMobileIDSucceedsAsComplete() {

        RequestContext mockRequestContext = getMockRequestContext();
        final MobileIDSession mockMobileIDSession = createMockMobileIDSession();
        fillRequestContextFlowScope(mockRequestContext, mockMobileIDSession, 1);
        MobileIDRESTSessionStatus pollStatus = MobileIDRESTSessionStatus.builder()
                .authenticationComplete(true)
                .wrappedSessionStatus(createMockMidSessionStatus("COMPLETE"))
                .build();

        when(authenticationClient.getAuthenticationIdentity(eq(mockMobileIDSession), eq(pollStatus)))
                .thenReturn(AuthenticationIdentity.builder()
                        .identityCode(MOCK_PERSONAL_CODE)
                        .givenName(MOCK_FIRST_NAME)
                        .surname(MOCK_LAST_NAME)
                        .build()
                );
        when(authenticationClient.pollAuthenticationSessionStatus(eq(mockMobileIDSession)))
                .thenReturn(pollStatus);

        Event event = this.authenticationService.checkLoginForMobileID(mockRequestContext);

        assertEquals("Invalid WebFlow event", CasWebflowConstants.TRANSITION_ID_SUCCESS, event.getId());
        assertEquals("Invalid poll count in flow scope", new Integer(1), mockRequestContext.getFlowScope().getInteger(Constants.AUTH_COUNT));
        TaraCredential credential = mockRequestContext.getFlowScope().get(CasWebflowConstants.VAR_ID_CREDENTIAL, TaraCredential.class);
        assertEquals("Invalid TaraCredential.principalCode", MOCK_COUNTRY_CODE + MOCK_PERSONAL_CODE, credential.getPrincipalCode());
        assertEquals("Invalid TaraCredential.firstName", MOCK_FIRST_NAME, credential.getFirstName());
        assertEquals("Invalid TaraCredential.lastName", MOCK_LAST_NAME, credential.getLastName());
        assertEquals("Invalid TaraCredential.id",MOCK_COUNTRY_CODE + MOCK_PERSONAL_CODE, credential.getId());
        assertEquals("Invalid TaraCredential.type", AuthenticationType.MobileID, credential.getType());
        this.verifyLogContents(StatisticsOperation.SUCCESSFUL_AUTH);
    }

    @Test
    public void checkLoginForMobileIDShouldFailWhenUserError() {
        RequestContext mockRequestContext = getMockRequestContext();
        final MobileIDSession mockMobileIDSession = createMockMobileIDSession();
        fillRequestContextFlowScope(mockRequestContext, mockMobileIDSession, 1);
        MobileIDRESTSessionStatus pollStatus = MobileIDRESTSessionStatus.builder()
                .authenticationComplete(true)
                .wrappedSessionStatus(createMockMidSessionStatus("COMPLETE"))
                .build();

        when(authenticationClient.pollAuthenticationSessionStatus(eq(mockMobileIDSession)))
                .thenThrow(
                        new UserAuthenticationFailedException(MobileIDErrorMessage.USER_CANCELLED, "error details", new MidInternalErrorException("error cause details"))
                );

        try {
            authenticationService.checkLoginForMobileID(mockRequestContext);
            Assert.fail("Should not reach this!");
        } catch (Exception e) {
            assertThat(e, instanceOf(UserAuthenticationFailedException.class));
            assertThat(e.getMessage(), containsString("error details"));
            assertEquals(MobileIDErrorMessage.USER_CANCELLED, (((UserAuthenticationFailedException)e).getErrorMessageKey()));
            this.verifyLogContentsOnFailure("error details");
        }
    }

    @NotNull
    private MidSessionStatus createMockMidSessionStatus(String result) {
        MidSessionStatus status = new MidSessionStatus();
        status.setResult(result);
        return status;
    }

    private PreAuthenticationCredential createPreAuthenticationCredentialWithIdAndNumber() {
        PreAuthenticationCredential taraCredential = new PreAuthenticationCredential();
        taraCredential.setPrincipalCode(MOCK_PERSONAL_CODE);
        taraCredential.setMobileNumber(MOCK_PHONE_NUMBER);
        taraCredential.setCountry(MOCK_COUNTRY_CODE);
        return taraCredential;
    }

    private MobileIDSession createMockMobileIDSession() {
        return MobileIDRESTSession.builder()
                .sessionId(MOCK_SESSION_CODE)
                .verificationCode(MOCK_VERIFICATION_CODE).build();
    }

    private void fillRequestContextFlowScope(RequestContext requestContext, MobileIDSession mobileIDSession, int authCount) {
        MobileIDRESTSession sessionWrapper = MobileIDRESTSession.builder().sessionId(mobileIDSession.getSessionId()).verificationCode(mobileIDSession.getVerificationCode()).build();
        requestContext.getFlowScope().put(Constants.MOBILE_ID_VERIFICATION_CODE, sessionWrapper.getVerificationCode());
        requestContext.getFlowScope().put(Constants.MOBILE_ID_AUTHENTICATION_SESSION, mobileIDSession);
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

    private Object getAttrFromFlowScope(RequestContext mockRequestContext, String mobileIdVerificationCode) {
        return mockRequestContext.getFlowScope().get(mobileIdVerificationCode);
    }

    private void addPreAuthenticationContext(RequestContext requestContext, PreAuthenticationCredential preAuthenticationCredentialWithIdAndNumber) {
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(
                "credential", preAuthenticationCredentialWithIdAndNumber
        );
    }

    private RequestContext createPreAuthenticationRequestContext(PreAuthenticationCredential credential) {
        RequestContext requestContext = getMockRequestContext();
        addPreAuthenticationContext(requestContext, credential);
        return requestContext;
    }
}
