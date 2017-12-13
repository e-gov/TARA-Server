package ee.ria.sso.authentication.credential;

import com.codeborne.security.mobileid.MobileIDSession;

import ee.ria.sso.authentication.AuthenticationType;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MobileIDCredential extends AbstractCredential {

    private String mobileNumber;

    public MobileIDCredential(MobileIDSession session, String mobileNumber) {
        super(AuthenticationType.MobileID, session.personalCode, session.firstName, session.lastName);
        this.mobileNumber = mobileNumber;
    }

    @Override
    public String getMobileNumber() {
        return mobileNumber;
    }

}
