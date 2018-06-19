package ee.ria.sso.service.impl;

import java.util.Optional;

import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import ee.ria.sso.common.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.service.ManagerService;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Service
public class ManagerServiceImpl extends AbstractService implements ManagerService {

    private final Logger log = LoggerFactory.getLogger(ManagerServiceImpl.class);
    private final ServicesManager servicesManager;

    public ManagerServiceImpl(ServicesManager servicesManager, TaraResourceBundleMessageSource messageSource) {
        super(messageSource);
        this.servicesManager = servicesManager;
    }

    @Override
    public Optional<OidcRegisteredService> getServiceByID(String serviceID) {
        this.log.debug("Searching OIDC service by <{}>", serviceID);
        Optional<OidcRegisteredService> service;

        try {
            service = Optional.ofNullable(this.servicesManager.findServiceBy(serviceID, OidcRegisteredService.class));
        } catch (RuntimeException e) {
            this.log.error("Internal CAS error", e);
            service = Optional.empty();
        }

        this.log.debug("Service has been found? <{}>", service.isPresent());
        return service;
    }

}
