package ee.ria.sso;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import com.codeborne.security.mobileid.MobileIDAuthenticator;
import com.codeborne.security.mobileid.MobileIDSession;

/**
 * Created by serkp on 21.09.2017.
 */
@Component
@Qualifier(value = "MIDAuthenticator")
public class MIDAuthenticator extends MobileIDAuthenticator {

	@Override
	protected MobileIDSession startLogin(String personalCode, String countryCode, String phone) {
		return super.startLogin(personalCode, countryCode, phone);
	}

}
