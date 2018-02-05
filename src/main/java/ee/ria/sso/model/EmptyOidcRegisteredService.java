package ee.ria.sso.model;

import org.apereo.cas.services.OidcRegisteredService;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class EmptyOidcRegisteredService extends OidcRegisteredService {

    public EmptyOidcRegisteredService() {
        this.setInformationUrl("#");
    }

}
