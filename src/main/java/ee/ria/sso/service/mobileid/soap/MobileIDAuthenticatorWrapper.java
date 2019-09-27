package ee.ria.sso.service.mobileid.soap;

import com.codeborne.security.mobileid.MobileIDAuthenticator;
import com.codeborne.security.mobileid.MobileIDSession;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * Wrapped only to initiate authentication with personal code AND phone number
 * because used method is protected.
 */

@ConditionalOnProperty("mobile-id.enabled")
public class MobileIDAuthenticatorWrapper extends MobileIDAuthenticator {

    @Override
    public MobileIDSession startLogin(String personalCode, String countryCode, String phone) {
        return super.startLogin(personalCode, countryCode, phone);
    }
}