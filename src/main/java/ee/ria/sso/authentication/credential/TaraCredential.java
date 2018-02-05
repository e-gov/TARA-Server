package ee.ria.sso.authentication.credential;

import org.apereo.cas.authentication.Credential;
import org.springframework.webflow.core.collection.AttributeMap;

import ee.ria.sso.authentication.AuthenticationType;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraCredential implements Credential {

    private final AuthenticationType type;
    private AttributeMap attributes;
    private String principalCode;
    private String firstName;
    private String lastName;
    private String mobileNumber;

    public TaraCredential() {
        this.type = AuthenticationType.Default;
    }

    public TaraCredential(String principalCode, String firstName, String lastName) {
        this.type = AuthenticationType.IDCard;
        this.principalCode = principalCode;
        this.firstName = firstName;
        this.lastName = lastName;

    }

    public TaraCredential(String principalCode, String firstName, String lastName, String mobileNumber) {
        this.type = AuthenticationType.MobileID;
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

    public AttributeMap getAttributes() {
        return attributes;
    }

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

}
