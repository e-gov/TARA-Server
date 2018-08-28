package ee.ria.sso.authentication.credential;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.authentication.LevelOfAssurance;
import org.apereo.cas.authentication.Credential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraCredential implements Credential {

    private final AuthenticationType type;
    private String principalCode;
    private String firstName;
    private String lastName;
    private String mobileNumber;
    private String country;
    private String dateOfBirth;
    private LevelOfAssurance levelOfAssurance;
    private BankEnum banklinkType;

    public TaraCredential() {
        this.type = AuthenticationType.Default;
    }

    // TODO refacto needed: use specific credentials for each auth impl
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        TaraCredential other = (TaraCredential) o;
        return this.principalCode != null ? this.principalCode.equals(other.principalCode)
            : other.principalCode == null;
    }

    @Override
    public int hashCode() {
        return this.principalCode != null ? this.principalCode.hashCode() : 0;
    }

    /*
     * ACCESSORS
     */

    public AuthenticationType getType() {
        return type;
    }

    public String getPrincipalCode() {
        return principalCode;
    }

    public void setPrincipalCode(String principalCode) {
        this.principalCode = principalCode;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public void setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public LevelOfAssurance getLevelOfAssurance() {
        return levelOfAssurance;
    }

    public void setLevelOfAssurance(LevelOfAssurance levelOfAssurance) {
        this.levelOfAssurance = levelOfAssurance;
    }

    public BankEnum getBanklinkType() {
        return banklinkType;
    }

    public void setBanklinkType(BankEnum banklinkType) {
        this.banklinkType = banklinkType;
    }

    @Override
    public String toString() {
        return "TaraCredential{" +
                "type=" + type +
                ", principalCode='" + principalCode + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", mobileNumber='" + mobileNumber + '\'' +
                ", country='" + country + '\'' +
                ", dateOfBirth='" + dateOfBirth + '\'' +
                ", levelOfAssurance=" + levelOfAssurance +
                ", banklinkType=" + banklinkType +
                '}';
    }
}
