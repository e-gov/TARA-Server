package ee.ria.sso.service.eidas;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.credential.TaraCredential;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.util.Assert;

@Getter
@EqualsAndHashCode
@ToString
public class EidasCredential extends TaraCredential {

    private final String dateOfBirth;
    private final LevelOfAssurance levelOfAssurance;

    public EidasCredential(String principalCode, String firstName, String lastName, String dateOfBirth, LevelOfAssurance levelOfAssurance) {
        super(AuthenticationType.eIDAS, principalCode, firstName, lastName);
        Assert.notNull(dateOfBirth, "Missing mandatory attribute! Date of birth is required in case of eIDAS");
        Assert.notNull(levelOfAssurance, "Missing mandatory attribute! LoA is required in case of eIDAS");
        this.dateOfBirth = dateOfBirth;
        this.levelOfAssurance = levelOfAssurance;
    }
}
