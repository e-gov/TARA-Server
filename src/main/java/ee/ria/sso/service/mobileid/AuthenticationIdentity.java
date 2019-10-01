package ee.ria.sso.service.mobileid;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AuthenticationIdentity {

    private final String identityCode;
    private final String givenName;
    private final String surname;
}
