package ee.ria.sso.config;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.service.manager.ManagerService;
import org.apache.commons.collections.keyvalue.DefaultMapEntry;
import org.apache.commons.collections4.MapUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.CasServerProperties;
import org.apereo.cas.services.OidcRegisteredService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

@RunWith(MockitoJUnitRunner.class)
public class ThymeleafSupportTest {

    private static final String CLIENT_ID = "openIdDemo";
    private static final String SERVICE_SHORT_NAME = "openIdDemoShortName";

    @Mock
    ManagerService managerService;

    @Mock
    CasConfigurationProperties casProperties;

    @Mock
    TaraProperties taraProperties;

    private ThymeleafSupport thymeleafSupport;

    @Before
    public void setUp() {
        thymeleafSupport = new ThymeleafSupport(managerService, casProperties, taraProperties, "paramName");
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenPassedParameterIsNull() {
        Assert.assertFalse(this.thymeleafSupport.isAuthMethodAllowed(null));
    }

    @Test
    public void isAuthMethodAllowedShouldReturnTrueWhenMethodsInSession() {
        Arrays.stream(AuthenticationType.values())
                .forEach(method -> {
                    setRequestContextWithSessionMap(Collections.singletonMap(
                            Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(method)
                    ));
                    Assert.assertTrue(this.thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedWhenNoAttrSetInSession() {
        Arrays.stream(AuthenticationType.values())
                .forEach(method -> {
                    setRequestContextWithSessionMap(new HashMap<>());
                    Assert.assertTrue("Method " + method + " should be allowed", this.thymeleafSupport.isAuthMethodAllowed(method));
                });
    }

    @Test
    public void isAuthMethodAllowedShouldReturnFalseWhenAllowedInSessionList() {
        final ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null,
                casProperties, taraProperties, null);
        setRequestContextWithSessionMap(Collections.singletonMap(
                Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.emptyList()
        ));
        Arrays.stream(AuthenticationType.values())
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
        Mockito.when(managerService.getServiceByName(CLIENT_ID))
                .thenReturn(Optional.of(oidcRegisteredService));

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, null, null, null);

        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url");
        sessionMap.put(Constants.TARA_OIDC_SESSION_CLIENT_ID, CLIENT_ID);

        setRequestContextWithSessionMap(sessionMap);
        Assert.assertEquals("https://client/url", thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnValidCancelUrlWhenValidRedirectUriPresentInSessionAndInformationUriNotPresent() {
        OidcRegisteredService oidcRegisteredService = Mockito.mock(OidcRegisteredService.class);
        Mockito.when(oidcRegisteredService.getInformationUrl()).thenReturn(null);

        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceByName(CLIENT_ID))
                .thenReturn(Optional.of(oidcRegisteredService));

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, null, null, null);

        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url");
        sessionMap.put(Constants.TARA_OIDC_SESSION_STATE, "randomSessionState");
        sessionMap.put(Constants.TARA_OIDC_SESSION_CLIENT_ID, CLIENT_ID);

        setRequestContextWithSessionMap(sessionMap);

        Assert.assertEquals("https://client/url?error=user_cancel&error_description=User+canceled+the+login+process&state=randomSessionState", thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getHomeUrlShouldReturnEmptyUrlWhenInvalidRedirectUriPresentInSession() {
        ManagerService managerService = Mockito.mock(ManagerService.class);

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, casProperties, null, null);

        setRequestContextWithSessionMap(Collections.singletonMap(Constants.TARA_OIDC_SESSION_REDIRECT_URI, "https://client/url"));
        Assert.assertEquals("#", thymeleafSupport.getHomeUrl());
    }

    @Test
    public void getServiceShortNameShouldReturnShortNameSuccessfully() {
        ManagerService managerService = Mockito.mock(ManagerService.class);
        Mockito.when(managerService.getServiceShortName(CLIENT_ID))
                .thenReturn(SERVICE_SHORT_NAME);

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(managerService, casProperties, null, null);

        setRequestContextWithSessionMap(Collections.singletonMap(Constants.TARA_OIDC_SESSION_CLIENT_ID, CLIENT_ID));
        Assert.assertEquals(SERVICE_SHORT_NAME, thymeleafSupport.getServiceShortName());
    }

    @Test
    public void getLocaleUrlShouldReturn() throws Exception {
        setRequestContextWithSessionMap(new HashMap<>());

        CasServerProperties casServerProperties =  new CasServerProperties();
        casServerProperties.setName("https://example.tara.url");
        Mockito.when(casProperties.getServer()).thenReturn(casServerProperties);

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, casProperties, null, "somelocaleparam");
        Assert.assertEquals("https://example.tara.url:443?somelocaleparam=et", thymeleafSupport.getLocaleUrl("et"));
    }

    @Test
    public void getLocaleUrlExistingRequestContainsInvalidCharactersAut292() throws Exception {

        mockSpringServletRequestAttributes();
        final MockRequestContext requestContext = new MockRequestContext();
        final MockExternalContext externalContext = new MockExternalContext();
        final SharedAttributeMap<Object> map = externalContext.getSessionMap();

        MockHttpServletRequest nativeRequest = new MockHttpServletRequest();
        nativeRequest.setQueryString("service=https%3A%2F%2Ftara.ria.ee%2Foauth2.0%2Fhttps://url.com/api/?get=start");
        externalContext.setNativeRequest(nativeRequest);
        requestContext.setExternalContext(externalContext);

        RequestContextHolder.setRequestContext(requestContext);
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(nativeRequest));


        CasServerProperties casServerProperties =  new CasServerProperties();
        casServerProperties.setName("https://example.tara.url");
        Mockito.when(casProperties.getServer()).thenReturn(casServerProperties);

        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, casProperties, null, "somelocaleparam");
        Assert.assertEquals("#", thymeleafSupport.getLocaleUrl("et"));
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
    public void getCurrentRequestIdentifierShouldReturnIdFromRequestAttributes() {
        String uniqueRequestId = UUID.randomUUID().toString();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(Constants.MDC_ATTRIBUTE_REQUEST_ID, uniqueRequestId);
        ThymeleafSupport thymeleafSupport = new ThymeleafSupport(null, null, taraProperties, null);
        Assert.assertEquals(uniqueRequestId, thymeleafSupport.getCurrentRequestIdentifier(request));
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
