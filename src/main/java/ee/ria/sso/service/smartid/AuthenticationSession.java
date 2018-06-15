package ee.ria.sso.service.smartid;

import ee.sk.smartid.AuthenticationHash;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@RequiredArgsConstructor
class AuthenticationSession implements Serializable {

    private final String sessionId;
    private final AuthenticationHash authenticationHash;

    @Setter
    private int statusCheckCount = 0;

    public void increaseStatusCheckCount() {
        statusCheckCount++;
    }
}
