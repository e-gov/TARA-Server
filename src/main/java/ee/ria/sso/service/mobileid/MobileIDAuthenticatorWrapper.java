package ee.ria.sso.service.mobileid;

import com.codeborne.security.mobileid.MobileIDAuthenticator;
import com.codeborne.security.mobileid.MobileIDSession;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Created by serkp on 21.09.2017.
 */

@ConditionalOnProperty("mobile-id.enabled")
@Component
public class MobileIDAuthenticatorWrapper extends MobileIDAuthenticator {

    @Override
    public MobileIDSession startLogin(String personalCode, String countryCode, String phone) {
        return super.startLogin(personalCode, countryCode, phone);
    }

}
