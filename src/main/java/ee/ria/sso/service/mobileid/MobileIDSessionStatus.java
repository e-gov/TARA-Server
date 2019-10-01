package ee.ria.sso.service.mobileid;

import java.io.Serializable;

public interface MobileIDSessionStatus extends Serializable {

    boolean isAuthenticationComplete();
}
