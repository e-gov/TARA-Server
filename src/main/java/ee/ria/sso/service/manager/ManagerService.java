package ee.ria.sso.service.manager;

import org.apereo.cas.services.OidcRegisteredService;

import java.util.Optional;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public interface ManagerService {

   Optional<OidcRegisteredService> getServiceByName(String serviceName);

}
