package ee.ria.sso;

import com.codeborne.security.mobileid.MobileIDAuthenticator;
import com.codeborne.security.mobileid.MobileIDSession;
import org.springframework.stereotype.Component;

/**
 * Created by serkp on 21.09.2017.
 */

@Component
public class MobileIDAuthenticatorWrapper extends MobileIDAuthenticator {

    @Override
    public MobileIDSession startLogin(String personalCode, String countryCode, String phone) {
        return super.startLogin(personalCode, countryCode, phone);
    }

}
