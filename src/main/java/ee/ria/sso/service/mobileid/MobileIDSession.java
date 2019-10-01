package ee.ria.sso.service.mobileid;

import java.io.Serializable;

public interface MobileIDSession extends Serializable {

    String getSessionId();
    String getVerificationCode();
}
