package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.service.mobileid.MobileIDSession;
import ee.sk.mid.MidAuthenticationHashToSign;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class MobileIDRESTSession implements MobileIDSession {

    private final String sessionId;
    private final String verificationCode;
    private final MidAuthenticationHashToSign authenticationHash;
}
