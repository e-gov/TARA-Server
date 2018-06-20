package ee.ria.sso.service.smartid;

import ee.sk.smartid.AuthenticationHash;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertSame;

public class AuthenticationSessionTest {

    @Test
    public void increaseCount() {
        AuthenticationSession authSession = AuthenticationSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .authenticationHash(AuthenticationHash.generateRandomHash())
                .statusCheckCount(0)
                .build();

        assertSame(0, authSession.getStatusCheckCount());

        authSession.increaseStatusCheckCount();
        assertSame(1, authSession.getStatusCheckCount());

        authSession.increaseStatusCheckCount();
        authSession.increaseStatusCheckCount();
        authSession.increaseStatusCheckCount();
        assertSame(4, authSession.getStatusCheckCount());
    }
}
