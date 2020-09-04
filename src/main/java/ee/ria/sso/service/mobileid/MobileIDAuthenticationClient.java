package ee.ria.sso.service.mobileid;

import java.io.IOException;
import java.security.cert.CertificateException;

public interface MobileIDAuthenticationClient<S extends MobileIDSession, T extends MobileIDSessionStatus> {

    S initAuthentication(String personalCode, String countryCode, String phoneNumber);

    T pollAuthenticationSessionStatus(S session);

    AuthenticationIdentity getAuthenticationIdentity(S session, T sessionStatus) throws IOException, CertificateException;
}
