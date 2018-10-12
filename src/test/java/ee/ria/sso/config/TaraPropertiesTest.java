package ee.ria.sso.config;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.manager.ManagerService;
import org.apereo.cas.services.OidcRegisteredService;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
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
    public void isAuthMethodAllowedShouldReturnTrueWhenMethodsEnabledAndAllowedInSession() {
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertTrue(this.taraProperties.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsEnabledButNotAllowedInSession() {
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> Assert.assertFalse(this.taraProperties.isAuthMethodAllowed(method)));
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledButAllowedInSession() {
        final TaraProperties taraProperties = new TaraProperties(null,
                Mockito.mock(Environment.class), null);
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertFalse(taraProperties.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledAndNotAllowedInSession() {
        final TaraProperties taraProperties = new TaraProperties(null,
                Mockito.mock(Environment.class), null);
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> Assert.assertFalse(taraProperties.isAuthMethodAllowed(method)));
    }

    @Test
    public void getHomeUrlShouldReturnEmptyUrlWhenRedirectUriNotPresentInSession() {
        setRequestContextWithSessionMap(null);
        Assert.assertEquals("#", this.taraProperties.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnValidHomeUrlWhenValidRedirectUriPresentInSession() {
        OidcRegisteredService oidcRegisteredService = Mockito.mock(OidcRegisteredService.class);
        Mockito.when(oidcRegisteredService.getInformationUrl()).thenReturn("https://client/url");

        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByID("https://client/url"))
                .thenReturn(Optional.of(oidcRegisteredService));

        TaraProperties taraProperties = new TaraProperties(null, null, managerService);

        setRequestContextWithSessionMap(
                Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url")
        );
        Assert.assertEquals("https://client/url", taraProperties.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnEmptyUrlWhenInvalidRedirectUriPresentInSession() {
        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByID("https://client/url"))
                .thenReturn(Optional.empty());

        TaraProperties taraProperties = new TaraProperties(null, null, managerService);

        setRequestContextWithSessionMap(
                Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url")
        );
        Assert.assertEquals("#", taraProperties.getHomeUrl());
    }

    private static void setRequestContextWithSessionMap(final Map<String, Object> sessionMap) {
        final MockRequestContext requestContext = new MockRequestContext();
        final MockExternalContext externalContext = new MockExternalContext();
        final SharedAttributeMap<Object> map = externalContext.getSessionMap();

        if (sessionMap != null) sessionMap.forEach(
                (k, v) -> map.put(k, v)
        );

        requestContext.setExternalContext(externalContext);
        RequestContextHolder.setRequestContext(requestContext);
    }

}
