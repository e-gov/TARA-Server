package ee.ria.sso.authentication.credential;

import org.apereo.cas.authentication.Credential;
import org.springframework.webflow.core.collection.AttributeMap;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractCredential implements Credential {

    public enum Type {
        Default, IDCard, MobileID
    }

    protected AttributeMap attributes;
    protected final Type type;
    protected final String principalCode;
    protected final String firstName;
    protected final String lastName;

    public AbstractCredential(Type type, String principalCode, String firstName, String lastName) {
        this.type = type;
        this.principalCode = principalCode;
        this.firstName = firstName;
        this.lastName = lastName;

    }

    public abstract String getMobileNumber();

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
        AbstractCredential other = (AbstractCredential) o;
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

    public Type getType() {
        return type;
    }

    public String getPrincipalCode() {
        return principalCode;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

}
