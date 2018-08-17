package ee.ria.sso.service.manager;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;

public class ManagerServiceImplTest {

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @Test
    public void getServiceByID_managerReturnsValidService_shouldReturnNonEmptyOptional() {
        ServicesManager servicesManager = createValidServicesManagerWith("ServiceID",
                Mockito.mock(OidcRegisteredService.class));
        ManagerService managerService = new ManagerServiceImpl(servicesManager, messageSource);

        Assert.assertTrue(managerService.getServiceByID("ServiceID").isPresent());
    }

    @Test
    public void getServiceByID_managerReturnsNoService_shouldReturnEmptyOptional() {
        ServicesManager servicesManager = createValidServicesManagerWith("ServiceID", null);
        ManagerService managerService = new ManagerServiceImpl(servicesManager, messageSource);

        Assert.assertFalse(managerService.getServiceByID("ServiceID").isPresent());
    }

    @Test
    public void getServiceByID_serviceManagerThrowsRuntimeException_shouldReturnEmptyOptional() {
        ServicesManager servicesManager = Mockito.mock(ServicesManager.class);
        Mockito.when(servicesManager.findServiceBy("ServiceID")).thenThrow(RuntimeException.class);
        ManagerService managerService = new ManagerServiceImpl(servicesManager, messageSource);

        Assert.assertFalse(managerService.getServiceByID("ServiceID").isPresent());
    }

    private static ServicesManager createValidServicesManagerWith(String serviceId, OidcRegisteredService service) {
        ServicesManager servicesManager = Mockito.mock(ServicesManager.class);
        Mockito.when(servicesManager.findServiceBy(serviceId, OidcRegisteredService.class))
                .thenReturn(service);

        return servicesManager;
    }
}