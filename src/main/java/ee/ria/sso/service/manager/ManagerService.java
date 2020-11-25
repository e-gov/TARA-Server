package ee.ria.sso.service.manager;

import org.apereo.cas.services.AbstractRegisteredService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredServiceProperty;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public interface ManagerService {

   Optional<OidcRegisteredService> getServiceByName(String serviceName);
   Optional<Map<String, RegisteredServiceProperty>> getServiceNames(String serviceName);
   Optional<String> getServiceShortName();
   Optional<List<AbstractRegisteredService>> getAllAbstractRegisteredServices();

}
