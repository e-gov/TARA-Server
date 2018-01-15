package ee.ria.sso.test;

import java.util.Collection;
import java.util.function.Predicate;

import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TestServicesManager implements ServicesManager {

    @Override
    public RegisteredService save(RegisteredService registeredService) {
        return null;
    }

    @Override
    public RegisteredService delete(long l) {
        return null;
    }

    @Override
    public RegisteredService findServiceBy(String s) {
        return null;
    }

    @Override
    public RegisteredService findServiceBy(Service service) {
        return null;
    }

    @Override
    public Collection<RegisteredService> findServiceBy(Predicate<RegisteredService> predicate) {
        return null;
    }

    @Override
    public <T extends RegisteredService> T findServiceBy(Service service, Class<T> aClass) {
        return null;
    }

    @Override
    public <T extends RegisteredService> T findServiceBy(String s, Class<T> aClass) {
        return null;
    }

    @Override
    public RegisteredService findServiceBy(long l) {
        return null;
    }

    @Override
    public Collection<RegisteredService> getAllServices() {
        return null;
    }

    @Override
    public boolean matchesExistingService(Service service) {
        return false;
    }

    @Override
    public boolean matchesExistingService(String s) {
        return false;
    }

    @Override
    public void load() {

    }

}
