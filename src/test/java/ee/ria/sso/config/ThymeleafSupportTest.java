package ee.ria.sso.config;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.service.manager.ManagerService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.OidcRegisteredService;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public class ThymeleafSupportTest extends AbstractTest {

    @Autowired
    CasConfigurationProperties casProperties;

    @Autowired TaraProperties taraProperties;

    @Autowired
    private ThymeleafSupport thymeleafSupport;

    @Test
    public void isAuthMethodAllowedShouldReturnTrueWhenMethodsEnabledAndAllowedInSession() {
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    Mockito.when(taraProperties.isPropertyEnabled(Mockito.eq(method.getPropertyName()+ ".enabled"))).thenReturn(true);
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertTrue(this.thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsEnabledButNotAllowedInSession() {
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> Assert.assertFalse(this.thymeleafSupport.isAuthMethodAllowed(method)));
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledButAllowedInSession() {
        final ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null,
                casProperties, taraProperties);
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertFalse(thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledAndNotAllowedInSession() {
        final ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null,
                casProperties, taraProperties);
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> Assert.assertFalse(thymeleafSupport.isAuthMethodAllowed(method)));
    }

    @Test
    public void getHomeUrlShouldReturnEmptyUrlWhenRedirectUriNotPresentInSession() {
        setRequestContextWithSessionMap(null);
        Assert.assertEquals("#", this.thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnValidHomeUrlWhenValidRedirectUriPresentInSession() {
        OidcRegisteredService oidcRegisteredService = Mockito.mock(OidcRegisteredService.class);
        Mockito.when(oidcRegisteredService.getInformationUrl()).thenReturn("https://client/url");

        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByID("https://client/url"))
                .thenReturn(Optional.of(oidcRegisteredService));

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, null, null);

        setRequestContextWithSessionMap(
                Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url")
        );
        Assert.assertEquals("https://client/url", thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnEmptyUrlWhenInvalidRedirectUriPresentInSession() {
        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByID("https://client/url"))
                .thenReturn(Optional.empty());

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, casProperties, null);

        setRequestContextWithSessionMap(
                Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url")
        );
        Assert.assertEquals("#", thymeleafSupport.getHomeUrl());
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
