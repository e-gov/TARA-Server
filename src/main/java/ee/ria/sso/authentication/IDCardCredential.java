package ee.ria.sso.authentication;

import ee.ria.sso.model.IDModel;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class IDCardCredential extends AbstractCredential {

    public IDCardCredential(IDModel model) {
        super(Type.IDCard, model.getSerialNumber(), model.getGivenName(), model.getSurname());
    }

}
