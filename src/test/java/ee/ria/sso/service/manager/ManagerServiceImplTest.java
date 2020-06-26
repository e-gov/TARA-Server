package ee.ria.sso.service.manager;

import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class ManagerServiceImplTest {

    private static final String SERVICE_NAME = "ServiceName";

    @Test
    public void getServiceByID_managerReturnsValidService_shouldReturnNonEmptyOptional() {
        Collection<RegisteredService> registeredServices = new ArrayList<>();
        OidcRegisteredService oidcRegisteredService = new OidcRegisteredService();
        oidcRegisteredService.setClientId(SERVICE_NAME);
        registeredServices.add(oidcRegisteredService);
        ServicesManager servicesManager = createValidServicesManagerWith(registeredServices);
        ManagerService managerService = new ManagerServiceImpl(servicesManager);

        Assert.assertTrue(managerService.getServiceByName(SERVICE_NAME).isPresent());
    }

    @Test
    public void getServiceByID_managerReturnsNoService_shouldReturnEmptyOptional() {
        Collection<RegisteredService> registeredServices = new ArrayList<>();
        ServicesManager servicesManager = createValidServicesManagerWith(registeredServices);
        ManagerService managerService = new ManagerServiceImpl(servicesManager);

        Assert.assertFalse(managerService.getServiceByName(SERVICE_NAME).isPresent());
    }

    @Test
    public void getServiceByID_managerReturnsDuplicateService_shouldReturnEmptyOptional() {
        Collection<RegisteredService> registeredServices = new ArrayList<>();
        OidcRegisteredService oidcRegisteredService = new OidcRegisteredService();
        oidcRegisteredService.setClientId(SERVICE_NAME);
        OidcRegisteredService duplicateOidcRegisteredService = new OidcRegisteredService();
        duplicateOidcRegisteredService.setClientId(SERVICE_NAME);
        registeredServices.add(oidcRegisteredService);
        registeredServices.add(duplicateOidcRegisteredService);

        ServicesManager servicesManager = createValidServicesManagerWith(registeredServices);
        ManagerService managerService = new ManagerServiceImpl(servicesManager);

        Assert.assertEquals(Optional.empty(), managerService.getServiceByName(SERVICE_NAME));
    }

    @Test
    public void getServiceByID_serviceManagerThrowsRuntimeException_shouldReturnEmptyOptional() {
        ServicesManager servicesManager = Mockito.mock(ServicesManager.class);
        Mockito.when(servicesManager.findServiceBy(SERVICE_NAME)).thenThrow(RuntimeException.class);
        ManagerService managerService = new ManagerServiceImpl(servicesManager);

        Assert.assertFalse(managerService.getServiceByName(SERVICE_NAME).isPresent());
    }

    private static ServicesManager createValidServicesManagerWith(Collection<RegisteredService> services) {
        ServicesManager servicesManager = Mockito.mock(ServicesManager.class);
        Mockito.when(servicesManager.getAllServices())
                .thenReturn(services);

        return servicesManager;
    }
}