package ee.ria.sso.service.mobileid;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.TaraCredential;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@EqualsAndHashCode
@ToString
public class MobileIDCredential extends TaraCredential {

    private final String phoneNumber;
    private final Boolean phoneNumberVerified = true;

    public MobileIDCredential(String principalCode, String firstName, String lastName) {
        super(AuthenticationType.MobileID, principalCode, firstName, lastName);
        this.phoneNumber = null;
    }

    public MobileIDCredential(String principalCode, String firstName, String lastName, String phoneNumber) {
        super(AuthenticationType.MobileID, principalCode, firstName, lastName);
        this.phoneNumber = phoneNumber;
    }
}
