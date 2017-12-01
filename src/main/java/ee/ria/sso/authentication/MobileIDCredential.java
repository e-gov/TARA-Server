package ee.ria.sso.authentication;

import com.codeborne.security.mobileid.MobileIDSession;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MobileIDCredential extends AbstractCredential {

    private String mobileNumber;

    public MobileIDCredential(MobileIDSession session, String mobileNumber) {
        super(Type.MobileID, session.personalCode, session.firstName, session.lastName);
        this.mobileNumber = mobileNumber;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

}
