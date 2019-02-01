package ee.ria.sso.authentication.credential;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apereo.cas.authentication.Credential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Getter
@Setter
@EqualsAndHashCode
@ToString
public class TaraCredential implements Credential {

    private final AuthenticationType type;
    private String principalCode;
    private String firstName;
    private String lastName;

    public TaraCredential() {
        this.type = AuthenticationType.Default;
    }

    public TaraCredential(AuthenticationType authenticationType, String principalCode, String firstName, String lastName) {
        this.type = authenticationType;
        this.principalCode = principalCode;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    @Override
    public String getId() {
        return this.principalCode;
    }
}
