package ee.ria.sso.authentication.credential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class DefaultCredential extends AbstractCredential {

    public DefaultCredential() {
        super(Type.Default, null, null, null);
    }

    @Override
    public String getMobileNumber() {
        return null;
    }

}
