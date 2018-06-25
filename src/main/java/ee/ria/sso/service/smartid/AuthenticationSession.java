package ee.ria.sso.service.smartid;

import ee.sk.smartid.AuthenticationHash;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Builder
class AuthenticationSession implements Serializable {

    private final String sessionId;
    private final AuthenticationHash authenticationHash;
    private final CertificateLevel certificateLevel;

    @Setter
    private int statusCheckCount = 0;

    public void increaseStatusCheckCount() {
        statusCheckCount++;
    }
}
