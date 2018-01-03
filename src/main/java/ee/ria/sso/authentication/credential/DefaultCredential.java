package ee.ria.sso.authentication.credential;

import org.apache.commons.lang3.NotImplementedException;
import org.springframework.webflow.core.collection.AttributeMap;

import ee.ria.sso.authentication.AuthenticationType;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class DefaultCredential extends AbstractCredential {

    public DefaultCredential() {
        super(AuthenticationType.Default, null, null, null);
    }

    @Override
    public String getMobileNumber() {
        return null;
    }

    @Override
    public String getPrincipalCode() {
        return null;
    }

    @Override
    public String getId() {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public AttributeMap getAttributes() {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public String getFirstName() {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public String getLastName() {
        throw new NotImplementedException("Not implemented");
    }

}
