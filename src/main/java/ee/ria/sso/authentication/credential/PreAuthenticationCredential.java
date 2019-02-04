package ee.ria.sso.authentication.credential;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.apereo.cas.authentication.Credential;

/**
 * PreAuthenticationCredential is added to the flow scope before any authentication
 * starts and used to forward pre-authentication data to authentication services.
 */
@Data
@EqualsAndHashCode
@ToString
public class PreAuthenticationCredential implements Credential {
    private String principalCode;
    private String mobileNumber;
    private String country;

    @Override
    public String getId() {
        return Credential.UNKNOWN_ID;
    }
}
