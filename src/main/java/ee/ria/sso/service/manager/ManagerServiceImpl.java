package ee.ria.sso.service.manager;

import ee.ria.sso.Constants;
import ee.ria.sso.utils.SessionMapUtil;
import org.apereo.cas.config.CasOAuthConfiguration;
import org.apereo.cas.services.AbstractRegisteredService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Service
public class ManagerServiceImpl implements ManagerService {

    private final Logger log = LoggerFactory.getLogger(ManagerServiceImpl.class);
    private final ServicesManager servicesManager;
    private final CasOAuthConfiguration casOAuthConfiguration;

    public ManagerServiceImpl(ServicesManager servicesManager, CasOAuthConfiguration casOAuthConfiguration) {
        this.servicesManager = servicesManager;
        this.casOAuthConfiguration = casOAuthConfiguration;
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

    @Override
    public Optional<Map<String, RegisteredServiceProperty>> getServiceNames(String serviceName) {
        Optional<OidcRegisteredService> service = getServiceByName(serviceName);
        return service.map(AbstractRegisteredService::getProperties);
    }


    @Override
    public Optional<List<AbstractRegisteredService>> getAllRegisteredServicesExceptType(Class<?> type) {
        return Optional.of(this.servicesManager.getAllServices().stream()
                .filter(r -> r instanceof AbstractRegisteredService && !(type.isInstance(r)) && !(r.getServiceId().equals(getRegistryServiceURL())))
                .map(s -> (AbstractRegisteredService) s)
                .collect(Collectors.toList()));
    }

    @Override
    public Optional<String> getServiceShortName() {
        String serviceName;
        Locale locale = LocaleContextHolder.getLocale();

        Map<String, RegisteredServiceProperty> serviceShortNames = getServiceNames(
                SessionMapUtil.getStringSessionMapValue(Constants.TARA_OIDC_SESSION_CLIENT_ID)).orElse(null);

        if (Locale.ENGLISH.getLanguage().equalsIgnoreCase(locale.getLanguage())) {
            serviceName = "service.shortName.en";
        } else if (Locale.forLanguageTag("ru").getLanguage().equalsIgnoreCase(locale.getLanguage())) {
            serviceName = "service.shortName.ru";
        } else {
            serviceName = "service.shortName";
        }

        if (serviceShortNames != null && serviceShortNames.containsKey(serviceName)) {
            return Optional.ofNullable(serviceShortNames.get(serviceName).getValue());
        }

        return Optional.empty();
    }

    private String getRegistryServiceURL() {
        return casOAuthConfiguration.oauthCallbackService().getId();
    }
}
