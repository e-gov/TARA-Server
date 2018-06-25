package ee.ria.sso.service.smartid;

import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.*;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@ConditionalOnProperty("smart-id.enabled")
@Component
@RequiredArgsConstructor
class SmartIDClient {

    private final SmartIdConnector smartIdConnector;
    private final SmartIDConfigurationProvider confProvider;

    public AuthenticationSessionResponse authenticateSubject(AuthenticationRequest authRequest) {
        NationalIdentity nationalIdentity = new NationalIdentity(authRequest.getPersonCountry(), authRequest.getPersonIdentifier());
        AuthenticationSessionRequest request = formAuthenticationSessionRequest(authRequest);
        return smartIdConnector.authenticate(nationalIdentity, request);
    }

    public SessionStatus getSessionStatus(String sessionId) {
        SessionStatusRequest request = formSessionStatusRequest(sessionId);
        return smartIdConnector.getSessionStatus(request);
    }

    private AuthenticationSessionRequest formAuthenticationSessionRequest(AuthenticationRequest authRequest) {
        AuthenticationSessionRequest request = new AuthenticationSessionRequest();
        request.setRelyingPartyUUID(confProvider.getRelyingPartyUuid());
        request.setRelyingPartyName(confProvider.getRelyingPartyName());
        request.setCertificateLevel(authRequest.getCertificateLevel().name());
        request.setDisplayText(confProvider.getAuthenticationConsentDialogDisplayText());
        AuthenticationHash authHash = authRequest.getAuthenticationHash();
        request.setHashType(authHash.getHashType().getHashTypeName());
        request.setHash(authHash.getHashInBase64());
        return request;
    }

    private SessionStatusRequest formSessionStatusRequest(String sessionId) {
        SessionStatusRequest request = new SessionStatusRequest(sessionId);
        request.setResponseSocketOpenTime(TimeUnit.MILLISECONDS, confProvider.getSessionStatusSocketOpenDuration());
        return request;
    }

    @Builder
    @Getter
    public static class AuthenticationRequest {

        private final String personIdentifier;
        private final String personCountry;
        private final AuthenticationHash authenticationHash;
        private final CertificateLevel certificateLevel;
    }
}
