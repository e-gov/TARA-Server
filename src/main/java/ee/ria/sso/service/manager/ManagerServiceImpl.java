package ee.ria.sso.service.manager;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import ee.ria.sso.service.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Service
public class ManagerServiceImpl implements ManagerService {

    private final Logger log = LoggerFactory.getLogger(ManagerServiceImpl.class);
    private final ServicesManager servicesManager;

    public ManagerServiceImpl(ServicesManager servicesManager) {
        this.servicesManager = servicesManager;
    }

    @Override
    public Optional<OidcRegisteredService> getServiceByName(String serviceName) {
        this.log.debug("Searching OIDC service by <{}>", serviceName);
        Optional<OidcRegisteredService> service;
        try {
            Collection<RegisteredService> allRegisteredServices = this.servicesManager.getAllServices();
            List<OidcRegisteredService> services = allRegisteredServices.stream()
                    .filter(r -> r instanceof OidcRegisteredService)
                    .filter(i -> ((OidcRegisteredService) i).getClientId().equals(serviceName))
                    .map(s -> (OidcRegisteredService) s)
                    .collect(Collectors.toList());

            if (services.size() != 1) {
                throw new IllegalArgumentException("Duplicate OIDC Client ID");
            }

            service = Optional.ofNullable(services.get(0));
        } catch (RuntimeException e) {
            this.log.error("Internal CAS error", e);
            service = Optional.empty();
        }
        this.log.debug("Service has been found? <{}>", service.isPresent());
        return service;
    }



}
