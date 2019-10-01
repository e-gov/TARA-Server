package ee.ria.sso.service.mobileid.soap;

import ee.ria.sso.service.mobileid.MobileIDSession;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class MobileIDSOAPSession implements MobileIDSession {

    private final com.codeborne.security.mobileid.MobileIDSession wrappedSession;

    @Override
    public String getSessionId() {
        return String.valueOf(wrappedSession.sessCode);
    }

    @Override
    public String getVerificationCode() {
        return wrappedSession.challenge;
    }
}
