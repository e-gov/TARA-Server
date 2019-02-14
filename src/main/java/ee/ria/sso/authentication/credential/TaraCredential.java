package ee.ria.sso.authentication.credential;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apereo.cas.authentication.Credential;

@Getter
@EqualsAndHashCode
@ToString
public class TaraCredential implements Credential {

    private final AuthenticationType type;
    private final String principalCode;
    private final String firstName;
    private final String lastName;

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
