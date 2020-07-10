package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.Constants;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.config.mobileid.TestMobileIDConfiguration;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.service.mobileid.AuthenticationIdentity;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidCertificateParser;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidLanguage;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.exception.MidMissingOrInvalidParameterException;
import ee.sk.mid.exception.MidSessionNotFoundException;
import ee.sk.mid.exception.MidUnauthorizedException;
import ee.sk.mid.rest.MidConnector;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.request.MidSessionStatusRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import org.apache.commons.codec.binary.Base64;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class MobileIDRESTAuthClientTest {

    private static final String PERSONAL_CODE = "60001019906";
    private static final String PHONE_NUMBER = "00000766";
    private static final String COUNTRY_CODE = "EE";
    private static final String CLIENT_ID = "openIdDemo";
    private static final String SERVICE_SHORT_NAME = "openIdDemoShortName";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Mock
    private MidClient midClient;

    @Mock
    private MidConnector midConnector;

    @Autowired
    private MobileIDConfigurationProvider confProvider;

    private MobileIDRESTAuthClient authClient;

    @Mock
    private ManagerService managerService;

    @Captor
    private ArgumentCaptor<MidAuthenticationRequest> authRequestCaptor;

    @Captor
    private ArgumentCaptor<MidSessionStatusRequest> sessionStatusRequestCaptor;

    @Before
    public void init() {
        when(midClient.getMobileIdConnector()).thenReturn(midConnector);
        authClient = new MobileIDRESTAuthClient(confProvider, midClient, managerService);
    }

    @Test
    public void initAuthentication_successful() {
        MidAuthenticationResponse mockAuthResponse = new MidAuthenticationResponse(UUID.randomUUID().toString());
        when(midConnector.authenticate(authRequestCaptor.capture())).thenReturn(mockAuthResponse);

        mockRequestWithSessionMap();

        when(managerService.getServiceNames(CLIENT_ID)).thenReturn(Optional.of(new HashMap<>()));

        MobileIDRESTSession session = authClient.initAuthentication(PERSONAL_CODE, COUNTRY_CODE, PHONE_NUMBER);
        assertEquals(mockAuthResponse.getSessionID(), session.getSessionId());
        MidAuthenticationHashToSign authenticationHash = session.getAuthenticationHash();
        assertNotNull(authenticationHash);
        assertEquals(session.getVerificationCode(), authenticationHash.calculateVerificationCode());

        verify(midConnector).authenticate(authRequestCaptor.capture());
        MidAuthenticationRequest authRequest = authRequestCaptor.getValue();
        assertEquals(PHONE_NUMBER, authRequest.getPhoneNumber());
        assertEquals(PERSONAL_CODE, authRequest.getNationalIdentityNumber());
        assertEquals(authenticationHash.getHashInBase64(), authRequest.getHash());
        assertSame(confProvider.getAuthenticationHashType(), authRequest.getHashType());
        assertSame(MidLanguage.valueOf(confProvider.getLanguage()), authRequest.getLanguage());
        assertEquals(confProvider.getMessageToDisplay(), authRequest.getDisplayText());
        assertEquals(confProvider.getMessageToDisplayEncoding(), authRequest.getDisplayTextFormat());
    }

    @Test
    public void initAuthentication_successful_with_short_name() {
        MidAuthenticationResponse mockAuthResponse = new MidAuthenticationResponse(UUID.randomUUID().toString());
        when(midConnector.authenticate(authRequestCaptor.capture())).thenReturn(mockAuthResponse);

        mockRequestWithSessionMap();

        RegisteredServiceProperty rsp = Mockito.mock(RegisteredServiceProperty.class);
        Map<String, RegisteredServiceProperty> serviceShortNames = new HashMap<>();
        serviceShortNames.put("service.shortName", rsp);
        LocaleContextHolder.setLocale(Locale.forLanguageTag("et"));

        when(managerService.getServiceNames(CLIENT_ID)).thenReturn(Optional.of(serviceShortNames));
        when(rsp.getValue()).thenReturn(SERVICE_SHORT_NAME);

        MobileIDRESTSession session = authClient.initAuthentication(PERSONAL_CODE, COUNTRY_CODE, PHONE_NUMBER);
        assertEquals(mockAuthResponse.getSessionID(), session.getSessionId());
        MidAuthenticationHashToSign authenticationHash = session.getAuthenticationHash();
        assertNotNull(authenticationHash);
        assertEquals(session.getVerificationCode(), authenticationHash.calculateVerificationCode());

        verify(midConnector).authenticate(authRequestCaptor.capture());
        MidAuthenticationRequest authRequest = authRequestCaptor.getValue();
        assertEquals(PHONE_NUMBER, authRequest.getPhoneNumber());
        assertEquals(PERSONAL_CODE, authRequest.getNationalIdentityNumber());
        assertEquals(authenticationHash.getHashInBase64(), authRequest.getHash());
        assertSame(confProvider.getAuthenticationHashType(), authRequest.getHashType());
        assertSame(MidLanguage.valueOf(confProvider.getLanguage()), authRequest.getLanguage());
        assertEquals(SERVICE_SHORT_NAME, authRequest.getDisplayText());
        assertEquals(confProvider.getMessageToDisplayEncoding(), authRequest.getDisplayTextFormat());
    }

    @Test
    public void initiAuthentication_failsWithMidInternalErrorException() {
        expectedException.expect(ExternalServiceHasFailedException.class);
        expectedException.expectMessage("MID service returned internal error that cannot be handled locally");

        when(midConnector.authenticate(any())).thenThrow(MidInternalErrorException.class);
        mockRequestWithSessionMap();

        when(managerService.getServiceNames(CLIENT_ID)).thenReturn(Optional.of(new HashMap<>()));

        authClient.initAuthentication(PERSONAL_CODE, COUNTRY_CODE, PHONE_NUMBER);
    }

    @Test
    public void initiAuthentication_failsWithIntegrationRelatedException() throws Exception {
        for (Exception e : Arrays.asList(new MidMissingOrInvalidParameterException("details"), new MidUnauthorizedException("details"))) {
            Mockito.reset(midConnector);
            mockRequestWithSessionMap();
            when(managerService.getServiceNames(CLIENT_ID)).thenReturn(Optional.of(new HashMap<>()));
            when(midConnector.authenticate(any())).thenThrow(e);
            try {
                authClient.initAuthentication(PERSONAL_CODE, COUNTRY_CODE, PHONE_NUMBER);
                fail("Should not reach this");
            } catch (Exception ex) {
                assertEquals(IllegalStateException.class, ex.getClass());
                assertEquals("Integrator-side error with MID integration or configuration", ex.getMessage());
            }
        }
    }

    @Test
    public void initiAuthentication_failsWithUnknwonException() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unexpected error occurred during authentication initiation");

        mockRequestWithSessionMap();
        when(managerService.getServiceNames(CLIENT_ID)).thenReturn(Optional.of(new HashMap<>()));
        when(midConnector.authenticate(any())).thenThrow(NullPointerException.class);

        authClient.initAuthentication(PERSONAL_CODE, COUNTRY_CODE, PHONE_NUMBER);
    }

    @Test
    public void pollAuthenticationSessionStatus_resultOK_authenticationComplete() {
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setState("COMPLETE");
        midSessionStatus.setResult("OK");
        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenReturn(midSessionStatus);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        MobileIDRESTSessionStatus sessionStatus = authClient.pollAuthenticationSessionStatus(session);

        assertEquals(midSessionStatus, sessionStatus.getWrappedSessionStatus());
        assertTrue(sessionStatus.isAuthenticationComplete());
        verify(midConnector).getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture());
        MidSessionStatusRequest sessionStatusRequest = sessionStatusRequestCaptor.getValue();
        assertEquals(session.getSessionId(), sessionStatusRequest.getSessionID());
        assertEquals(Integer.valueOf(confProvider.getSessionStatusSocketOpenDuration() * 1000), Integer.valueOf(sessionStatusRequest.getTimeoutMs()));
    }

    @Test
    public void pollAuthenticationSessionStatus_resultMissing_authenticationNotComplete() {
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setState("COMPLETE");
        midSessionStatus.setResult(null);
        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenReturn(midSessionStatus);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        MobileIDRESTSessionStatus sessionStatus = authClient.pollAuthenticationSessionStatus(session);

        assertEquals(midSessionStatus, sessionStatus.getWrappedSessionStatus());
        assertFalse(sessionStatus.isAuthenticationComplete());
        verify(midConnector).getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture());
        MidSessionStatusRequest sessionStatusRequest = sessionStatusRequestCaptor.getValue();
        assertEquals(session.getSessionId(), sessionStatusRequest.getSessionID());
        assertEquals(Integer.valueOf(confProvider.getSessionStatusSocketOpenDuration() * 1000), Integer.valueOf(sessionStatusRequest.getTimeoutMs()));
    }

    @Test
    public void pollAuthenticationSessionStatus_resultFaulty_authenticationNotComplete() {
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setState("COMPLETE");
        midSessionStatus.setResult("NOT_MID_CLIENT");
        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenReturn(midSessionStatus);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();

        try {
            authClient.pollAuthenticationSessionStatus(session);
        } catch (UserAuthenticationFailedException e) {
            assertEquals("User is not a MID client or user's certificates are revoked.", e.getMessage());
            verify(midConnector).getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture());
            MidSessionStatusRequest sessionStatusRequest = sessionStatusRequestCaptor.getValue();
            assertEquals(session.getSessionId(), sessionStatusRequest.getSessionID());
            assertEquals(Integer.valueOf(confProvider.getSessionStatusSocketOpenDuration() * 1000), Integer.valueOf(sessionStatusRequest.getTimeoutMs()));
        }
    }

    @Test
    public void pollAuthenticationSessionStatusThrowsMidInternalErrorException_externalServiceHasFailedExceptionThrown() {
        expectedException.expect(ExternalServiceHasFailedException.class);
        expectedException.expectMessage("MID service returned internal error that cannot be handled locally");

        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenThrow(MidInternalErrorException.class);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        authClient.pollAuthenticationSessionStatus(session);
    }

    @Test
    public void pollAuthenticationSessionStatusThrowsMidUnauthorizedException_illegalStateExceptionThrown() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Integrator-side error with MID integration or configuration");

        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenThrow(MidUnauthorizedException.class);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        authClient.pollAuthenticationSessionStatus(session);
    }

    @Test
    public void pollAuthenticationSessionStatusThrowsMidSessionNotFoundException_illegalStateExceptionThrown() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Integrator-side error with MID integration or configuration");

        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenThrow(MidSessionNotFoundException.class);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        authClient.pollAuthenticationSessionStatus(session);
    }

    @Test
    public void pollAuthenticationSessionStatusThrowsUnhandledException_illegalStateExceptionThrown() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unexpected error occurred during authentication session status polling");

        when(midConnector.getAuthenticationSessionStatus(sessionStatusRequestCaptor.capture())).thenThrow(NullPointerException.class);

        MobileIDRESTSession session = MobileIDRESTSession.builder().sessionId(UUID.randomUUID().toString()).build();
        authClient.pollAuthenticationSessionStatus(session);
    }

    @Test
    public void getAuthenticationIdentity_successful() {
        MidAuthenticationHashToSign authenticationHash = MidAuthenticationHashToSign.newBuilder()
                .withHashInBase64("2VycgINMWA0mO9979MG9wpmu4d5rXMt3TXd0u3TYDSw=")
                .withHashType(confProvider.getAuthenticationHashType())
                .build();
        MobileIDRESTSession session = MobileIDRESTSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .authenticationHash(authenticationHash)
                .build();
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setCert("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");

        MobileIDRESTSessionStatus sessionStatus = MobileIDRESTSessionStatus.builder()
                .wrappedSessionStatus(midSessionStatus)
                .build();
        MidAuthentication mockAuthentication = MidAuthentication.newBuilder()
                .withSignatureValueInBase64("RYPBhVnrY4yobitFlVGLbFeCAz07/QWOJby/bIpk1kpG2vWXGbikVu0Ml4Y7bVgya2GUUZkXhGl8Oha+lJ5gmA==")
                .withAlgorithmName("SHA256WithECEncryption")
                .withCertificate(MidCertificateParser.parseX509Certificate(midSessionStatus.getCert()))
                .withHashType(confProvider.getAuthenticationHashType())
                .withSignedHashInBase64(session.getAuthenticationHash().getHashInBase64())
                .withResult("OK")
                .build();
        when(midClient.createMobileIdAuthentication(sessionStatus.getWrappedSessionStatus(), session.getAuthenticationHash())).thenReturn(mockAuthentication);

        AuthenticationIdentity authIdentity = authClient.getAuthenticationIdentity(session, sessionStatus);
        assertEquals("MARY ÄNN", authIdentity.getGivenName());
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", authIdentity.getSurname());
        assertEquals("60001019906", authIdentity.getIdentityCode());
    }

    @Test
    public void getAuthenticationIdentity_signatureDoesNotMatch() {
        expectedException.expectMessage("Authentication result validation failed with: [Signature verification failed]");
        expectedException.expect(AuthenticationValidationException.class);

        MidAuthenticationHashToSign authenticationHash = MidAuthenticationHashToSign.newBuilder()
                .withHashInBase64("2VycgINMWA0mO9979MG9wpmu4d5rXMt3TXd0u3TYDSw=")
                .withHashType(confProvider.getAuthenticationHashType())
                .build();
        MobileIDRESTSession session = MobileIDRESTSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .authenticationHash(authenticationHash)
                .build();
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setCert("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");

        MobileIDRESTSessionStatus sessionStatus = MobileIDRESTSessionStatus.builder()
                .wrappedSessionStatus(midSessionStatus)
                .build();
        MidAuthentication mockAuthentication = MidAuthentication.newBuilder()
                .withSignatureValueInBase64(Base64.encodeBase64String("invalid signature".getBytes(StandardCharsets.UTF_8)))
                .withAlgorithmName("SHA256WithECEncryption")
                .withCertificate(MidCertificateParser.parseX509Certificate(midSessionStatus.getCert()))
                .withHashType(confProvider.getAuthenticationHashType())
                .withSignedHashInBase64(session.getAuthenticationHash().getHashInBase64())
                .withResult("OK")
                .build();
        when(midClient.createMobileIdAuthentication(sessionStatus.getWrappedSessionStatus(), session.getAuthenticationHash())).thenReturn(mockAuthentication);

        authClient.getAuthenticationIdentity(session, sessionStatus);
    }

    @Test
    public void createMobileIdAuthenticationThrowsMidInternalErrorException_externalServiceHasFailedExceptionThrown() {
        expectedException.expect(ExternalServiceHasFailedException.class);
        expectedException.expectMessage("MID service returned internal error that cannot be handled locally");

        when(midClient.createMobileIdAuthentication(any(), any())).thenThrow(MidInternalErrorException.class);
        authClient.getAuthenticationIdentity(MobileIDRESTSession.builder().build(), MobileIDRESTSessionStatus.builder().build());
    }

    @Test
    public void createMobileIdAuthenticationThrowsUnhandledException_illegalStateExceptionThrown() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unexpected error occurred during creating Mobile-ID authentication");

        when(midClient.createMobileIdAuthentication(any(), any())).thenThrow(NullPointerException.class);
        authClient.getAuthenticationIdentity(MobileIDRESTSession.builder().build(), MobileIDRESTSessionStatus.builder().build());
    }

    private static void mockSpringServletRequestAttributes() {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    private static void setRequestContextWithSessionMap(final Map<String, Object> sessionMap) {
        mockSpringServletRequestAttributes();
        final MockRequestContext requestContext = new MockRequestContext();
        final MockExternalContext externalContext = new MockExternalContext();
        final SharedAttributeMap<Object> map = externalContext.getSessionMap();

        if (sessionMap != null) sessionMap.forEach(map::put);

        externalContext.setNativeRequest(new MockHttpServletRequest());
        requestContext.setExternalContext(externalContext);
        RequestContextHolder.setRequestContext(requestContext);
    }

    private static void mockRequestWithSessionMap() {
        Map<String, Object> sessionMap = new HashMap<>();
        sessionMap.put(Constants.TARA_OIDC_SESSION_CLIENT_ID, CLIENT_ID);

        setRequestContextWithSessionMap(sessionMap);
    }
}
