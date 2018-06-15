package ee.ria.sso.service.smartid;

import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.*;
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

import java.util.UUID;
import java.util.concurrent.TimeUnit;

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

    @Mock
    private SmartIdConnector smartIdConnector;

    @Autowired
    private SmartIDConfigurationProvider confProvider;

    private SmartIDClient smartIDClient;

    @Captor
    private ArgumentCaptor<AuthenticationSessionRequest> authRequestArgumentCaptor;

    @Captor
    private ArgumentCaptor<SessionStatusRequest> sessionStatusRequestArgumentCaptor;

    @Before
    public void init() {
        smartIDClient = new SmartIDClient(smartIdConnector, confProvider);
    }

    @Test
    public void authenticateSubject() {
        AuthenticationSessionResponse mockAuthResponse = new AuthenticationSessionResponse();
        mockAuthResponse.setSessionId(UUID.randomUUID().toString());
        when(smartIdConnector.authenticate(any(NationalIdentity.class), any())).thenReturn(mockAuthResponse);

        AuthenticationHash authHash = AuthenticationHash.generateRandomHash();
        AuthenticationSessionResponse authResponse = smartIDClient.authenticateSubject("EE", SmartIDMockData.VALID_EE_PERSON_IDENTIFIER, authHash);

        assertEquals(mockAuthResponse, authResponse);
        verifyAuthenticationRequest(authHash);
    }

    @Test
    public void getSessionStatus() {
        SessionStatus mockSessionStatusResponse = new SessionStatus();
        when(smartIdConnector.getSessionStatus(any())).thenReturn(mockSessionStatusResponse);

        String sessionId = UUID.randomUUID().toString();
        SessionStatus sessionStatus = smartIDClient.getSessionStatus(sessionId);

        assertEquals(mockSessionStatusResponse, sessionStatus);
        verifySessionStatusRequest(sessionId);
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

    private void verifySessionStatusRequest(String sessionId) {
        verify(smartIdConnector).getSessionStatus(sessionStatusRequestArgumentCaptor.capture());
        SessionStatusRequest sessionStatusRequest = sessionStatusRequestArgumentCaptor.getValue();
        assertEquals(sessionId, sessionStatusRequest.getSessionId());
        assertEquals(TimeUnit.MILLISECONDS, sessionStatusRequest.getResponseSocketOpenTimeUnit());
        assertEquals(confProvider.getSessionStatusSocketOpenDuration().longValue(), sessionStatusRequest.getResponseSocketOpenTimeValue());
    }
}
