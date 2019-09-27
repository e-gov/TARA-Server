package ee.ria.sso.service.mobileid;

public interface MobileIDAuthenticationClient<S extends MobileIDSession, T extends MobileIDSessionStatus> {

    S initAuthentication(String personalCode, String countryCode, String phoneNumber);

    T pollAuthenticationSessionStatus(S session);

    AuthenticationIdentity getAuthenticationIdentity(S session, T sessionStatus);
}
