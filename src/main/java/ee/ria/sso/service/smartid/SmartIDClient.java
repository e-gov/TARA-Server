package ee.ria.sso.service.smartid;

import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.*;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@ConditionalOnProperty("smart-id.enabled")
@Component
@RequiredArgsConstructor
class SmartIDClient {

    private static final String DEFAULT_CERTIFICATE_LEVEL = CertificateLevel.QUALIFIED.name();

    private final SmartIdConnector smartIdConnector;
    private final SmartIDConfigurationProvider confProvider;

    public AuthenticationSessionResponse authenticateSubject(String personCountry, String personIdentifier, AuthenticationHash authHash) {
        NationalIdentity nationalIdentity = new NationalIdentity(personCountry, personIdentifier);
        AuthenticationSessionRequest request = formAuthenticationSessionRequest(authHash);
        return smartIdConnector.authenticate(nationalIdentity, request);
    }

    public SessionStatus getSessionStatus(String sessionId) {
        SessionStatusRequest request = formSessionStatusRequest(sessionId);
        return smartIdConnector.getSessionStatus(request);
    }

    private AuthenticationSessionRequest formAuthenticationSessionRequest(AuthenticationHash authHash) {
        AuthenticationSessionRequest request = new AuthenticationSessionRequest();
        request.setRelyingPartyUUID(confProvider.getRelyingPartyUuid());
        request.setRelyingPartyName(confProvider.getRelyingPartyName());
        request.setCertificateLevel(DEFAULT_CERTIFICATE_LEVEL);
        request.setHashType(authHash.getHashType().getHashTypeName());
        request.setHash(authHash.getHashInBase64());
        request.setDisplayText(confProvider.getAuthenticationConsentDialogDisplayText());
        return request;
    }

    private SessionStatusRequest formSessionStatusRequest(String sessionId) {
        SessionStatusRequest request = new SessionStatusRequest(sessionId);
        request.setResponseSocketOpenTime(TimeUnit.MILLISECONDS, confProvider.getSessionStatusSocketOpenDuration());
        return request;
    }
}
