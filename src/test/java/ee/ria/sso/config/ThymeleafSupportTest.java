package ee.ria.sso.config;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.service.manager.ManagerService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.CasServerProperties;
import org.apereo.cas.services.OidcRegisteredService;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

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
    public void isAuthMethodAllowedWhenNoAttrSetInSession() {
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    Mockito.when(taraProperties.isPropertyEnabled(Mockito.eq(method.getPropertyName()+ ".enabled"))).thenReturn(true);
                    setRequestContextWithSessionMap(new HashMap<>());
                    Assert.assertTrue("Method " + method + " should be allowed", this.thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledButAllowedInSession() {
        final ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null,
                casProperties, taraProperties, null);
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> {
                    Mockito.when(taraProperties.isPropertyEnabled(Mockito.eq(method.getPropertyName()+ ".enabled"))).thenReturn(false);
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertFalse("Method " + method + " should not be allowed", thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenMethodsDisabledAndNotAllowedInSession() {
        final ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null,
                casProperties, taraProperties, null);
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values()).filter(at -> at != AuthenticationType.Default)
                .forEach(method -> Assert.assertFalse("Method " + method + " should be allowed", thymeleafSupport.isAuthMethodAllowed(method)));
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

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, null, null, null);

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

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, casProperties, null, null);

        setRequestContextWithSessionMap(Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url"));
        Assert.assertEquals("#", thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getLocaleUrlShouldReturn() throws Exception {
        setRequestContextWithSessionMap(new HashMap<>());

        casProperties.getServer().setName("https://example.tara.url");

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, casProperties, null, "somelocaleparam");
        Assert.assertEquals("https://example.tara.url:443?somelocaleparam=et", thymeleafSupport.getLocaleUrl("et"));
    }

    @Test
    public void getBackUrlShouldReturnPac4jRequestedUrlWithSpecifiedLocale() throws Exception {
        setRequestContextWithSessionMap(new HashMap<>());
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, casProperties, null, "somelocaleparam");
        Assert.assertEquals("https://example.tara.ee?somelocaleparam=et", thymeleafSupport.getBackUrl("https://example.tara.ee", Locale.forLanguageTag("et")));
    }

    @Test
    public void getBackUrlShouldReturnHashTagWhenEmpty() throws Exception {
        setRequestContextWithSessionMap(new HashMap<>());
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, casProperties, null, "somelocaleparam");
        Assert.assertEquals("#", thymeleafSupport.getBackUrl("", Locale.forLanguageTag("et")));
        Assert.assertEquals("#", thymeleafSupport.getBackUrl("          ", Locale.forLanguageTag("et")));
        Assert.assertEquals("#", thymeleafSupport.getBackUrl(null, Locale.forLanguageTag("et")));
    }

    @Test
    public void isNotLocaleShouldReturnTrue() {
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, null, null);
        Assert.assertTrue(thymeleafSupport.isNotLocale("en", Locale.forLanguageTag("et")));
        Assert.assertTrue(thymeleafSupport.isNotLocale("xxx", Locale.forLanguageTag("et")));
    }

    @Test
    public void isNotLocaleShouldReturnFalse() {
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, null, null);
        Assert.assertFalse(thymeleafSupport.isNotLocale("ET", Locale.forLanguageTag("et")));
        Assert.assertFalse(thymeleafSupport.isNotLocale("et", Locale.forLanguageTag("et")));
    }

    @Test
    public void getTestEnvironmentAlertMessageIfAvailableShouldReturnProperyValue() {
        String testMessage = "test123";
        Mockito.when(taraProperties.getTestEnvironmentWarningMessage()).thenReturn(testMessage);
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, taraProperties, null);
        Assert.assertEquals(testMessage, thymeleafSupport.getTestEnvironmentAlertMessageIfAvailable());
    }

    @Test
    public void getTestEnvironmentAlertMessageIfAvailableShouldReturnNull() {
        Mockito.when(taraProperties.getTestEnvironmentWarningMessage()).thenReturn(null);
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, taraProperties, null);
        Assert.assertEquals(null, thymeleafSupport.getTestEnvironmentAlertMessageIfAvailable());
    }

    @Test
    public void getCurrentRequestIdentifierShouldReturnIdFromMDC() {
        String uniqueRequestId = UUID.randomUUID().toString();
        MDC.put(Constants.MDC_ATTRIBUTE_REQUEST_ID, uniqueRequestId);
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, taraProperties, null);
        Assert.assertEquals(uniqueRequestId, thymeleafSupport.getCurrentRequestIdentifier());
    }

    private static void setRequestContextWithSessionMap(final Map<String, Object> sessionMap) {
        mockSpringServletRequestAttributes();
        final MockRequestContext requestContext = new MockRequestContext();
        final MockExternalContext externalContext = new MockExternalContext();
        final SharedAttributeMap<Object> map = externalContext.getSessionMap();

        if (sessionMap != null) sessionMap.forEach(
                (k, v) -> map.put(k, v)
        );

        externalContext.setNativeRequest(new MockHttpServletRequest());
        requestContext.setExternalContext(externalContext);
        RequestContextHolder.setRequestContext(requestContext);
    }

    private static void mockSpringServletRequestAttributes() {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

}
