package ee.ria.sso.service.manager;

import java.util.Optional;

import org.apereo.cas.services.OidcRegisteredService;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public interface ManagerService {

    Optional<OidcRegisteredService> getServiceByID(String serviceID);

}
