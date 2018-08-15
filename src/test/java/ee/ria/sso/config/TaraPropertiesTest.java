package ee.ria.sso.config;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.service.manager.ManagerService;
import org.apereo.cas.services.OidcRegisteredService;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.core.collection.ParameterMap;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import java.util.Optional;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraPropertiesTest extends AbstractTest {

    @Autowired
    private TaraProperties taraProperties;

    @Test
    public void testApplicationVersion() {
        Assert.assertNotEquals("Is not different", "-", this.taraProperties.getApplicationVersion());
    }

    @Test
    public void getHomeUrl_invalidServiceUrl_shouldReturnEmptyHomeUrl() {
        setRequestContextWith("invalid\\service\\url");
        Assert.assertEquals("#", this.taraProperties.getHomeUrl());
    }

    @Test
    public void getHomeUrl_validServiceUrl_shouldReturnValidHomeUrl() {
        OidcRegisteredService oidcRegisteredService = Mockito.mock(OidcRegisteredService.class);
        Mockito.when(oidcRegisteredService.getInformationUrl()).thenReturn("https://client/url");

        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByID("https://client/url"))
                .thenReturn(Optional.of(oidcRegisteredService));

        TaraProperties taraProperties = new TaraProperties(null, null, managerService);

        setRequestContextWith("https://service/url?redirect_uri=https%3A%2F%2Fclient%2Furl");
        Assert.assertEquals("https://client/url", taraProperties.getHomeUrl());
    }

    private static void setRequestContextWith(String serviceUrl) {
        ParameterMap parameterMap = Mockito.mock(ParameterMap.class);
        Mockito.when(parameterMap.getRequired("service")).thenReturn(serviceUrl);
        Mockito.when(parameterMap.contains("service")).thenReturn(true);

        RequestContext requestContext = Mockito.mock(RequestContext.class);
        Mockito.when(requestContext.getRequestParameters()).thenReturn(parameterMap);

        RequestContextHolder.setRequestContext(requestContext);
    }

}
