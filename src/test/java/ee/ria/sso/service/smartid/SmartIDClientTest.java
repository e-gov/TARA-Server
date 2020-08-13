package ee.ria.sso.service.smartid;

import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.ria.sso.service.manager.ManagerService;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SessionStatusRequest;
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

import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestSmartIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class SmartIDClientTest {

    private static final String SERVICE_SHORT_NAME = "openIdDemoShortName";

    @Mock
    private SmartIdConnector smartIdConnector;

    @Autowired
    private SmartIDConfigurationProvider confProvider;

    private SmartIDClient smartIDClient;

    @Mock
    private ManagerService managerService;

    @Captor
    private ArgumentCaptor<AuthenticationSessionRequest> authRequestArgumentCaptor;

    @Captor
    private ArgumentCaptor<SessionStatusRequest> sessionStatusRequestArgumentCaptor;

    @Before
    public void init() {
        smartIDClient = new SmartIDClient(smartIdConnector, confProvider, managerService);
    }

    @Test
    public void authenticateSubject() {
        AuthenticationSessionResponse mockAuthResponse = new AuthenticationSessionResponse();
        mockAuthResponse.setSessionID(UUID.randomUUID().toString());
        when(smartIdConnector.authenticate(any(NationalIdentity.class), any())).thenReturn(mockAuthResponse);

        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        SmartIDClient.AuthenticationRequest authRequest = SmartIDClient.AuthenticationRequest.builder()
                .personCountry("EE")
                .personIdentifier(SmartIDMockData.VALID_EE_PERSON_IDENTIFIER)
                .authenticationHash(authHash)
                .certificateLevel(CertificateLevel.QUALIFIED)
                .build();
        AuthenticationSessionResponse authResponse = smartIDClient.authenticateSubject(authRequest);

        assertEquals(mockAuthResponse, authResponse);
        verifyAuthenticationRequest(authHash);
    }

    @Test
    public void authenticateSubjectWithShortName() {
        AuthenticationSessionResponse mockAuthResponse = new AuthenticationSessionResponse();
        mockAuthResponse.setSessionID(UUID.randomUUID().toString());
        when(smartIdConnector.authenticate(any(NationalIdentity.class), any())).thenReturn(mockAuthResponse);
        when(managerService.getServiceShortName()).thenReturn(Optional.of(SERVICE_SHORT_NAME));

        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        SmartIDClient.AuthenticationRequest authRequest = SmartIDClient.AuthenticationRequest.builder()
                .personCountry("EE")
                .personIdentifier(SmartIDMockData.VALID_EE_PERSON_IDENTIFIER)
                .authenticationHash(authHash)
                .certificateLevel(CertificateLevel.QUALIFIED)
                .build();
        AuthenticationSessionResponse authResponse = smartIDClient.authenticateSubject(authRequest);

        assertEquals(mockAuthResponse, authResponse);
        verifyAuthenticationRequestWithShortName(authHash);
    }

    @Test
    public void getSessionStatus() {
        SessionStatus mockSessionStatusResponse = new SessionStatus();
        when(smartIdConnector.getSessionStatus(any())).thenReturn(mockSessionStatusResponse);

        String sessionId = UUID.randomUUID().toString();
        SessionStatus sessionStatus = smartIDClient.getSessionStatus(sessionId);

        assertEquals(mockSessionStatusResponse, sessionStatus);
        verify(smartIdConnector).getSessionStatus(Mockito.eq(sessionId));
    }

    private void verifyAuthenticationRequest(AuthenticationHash authHash) {
        verify(smartIdConnector).authenticate(any(NationalIdentity.class), authRequestArgumentCaptor.capture());
        AuthenticationSessionRequest authRequest = authRequestArgumentCaptor.getValue();
        assertEquals(confProvider.getRelyingPartyName(), authRequest.getRelyingPartyName());
        assertEquals(confProvider.getRelyingPartyUuid(), authRequest.getRelyingPartyUUID());
        assertEquals(confProvider.getAuthenticationConsentDialogDisplayText(), authRequest.getDisplayText());
        assertEquals(authHash.getHashType().getHashTypeName(), authRequest.getHashType());
        assertEquals(authHash.getHashInBase64(), authRequest.getHash());
        assertEquals(CertificateLevel.QUALIFIED.name(), authRequest.getCertificateLevel());
        assertNull(authRequest.getNonce());
    }

    private void verifyAuthenticationRequestWithShortName(AuthenticationHash authHash) {
        verify(smartIdConnector).authenticate(any(NationalIdentity.class), authRequestArgumentCaptor.capture());
        AuthenticationSessionRequest authRequest = authRequestArgumentCaptor.getValue();
        assertEquals(confProvider.getRelyingPartyName(), authRequest.getRelyingPartyName());
        assertEquals(confProvider.getRelyingPartyUuid(), authRequest.getRelyingPartyUUID());
        assertEquals(SERVICE_SHORT_NAME, authRequest.getDisplayText());
        assertEquals(authHash.getHashType().getHashTypeName(), authRequest.getHashType());
        assertEquals(authHash.getHashInBase64(), authRequest.getHash());
        assertEquals(CertificateLevel.QUALIFIED.name(), authRequest.getCertificateLevel());
        assertNull(authRequest.getNonce());
    }
}
