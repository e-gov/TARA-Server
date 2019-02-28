package org.apereo.cas.support.oauth.web.endpoints;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.oidc.MockPrincipalUtils;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.profile.OAuth20UserProfileDataCreator;
import org.apereo.cas.support.oauth.web.views.OAuth20UserProfileViewRenderer;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.accesstoken.AccessTokenImpl;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.ticket.support.NeverExpiresExpirationPolicy;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.pac4j.core.context.HttpConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.ArrayList;


public class OAuth20UserProfileEndpointControllerTest extends AbstractTest {

    public static final String MOCK_ACCESS_TOKEN = "mockAccessToken129";
    @Autowired
    ServicesManager servicesManager;

    @Autowired
    TicketRegistry ticketRegistry;

    @Autowired
    AccessTokenFactory accessTokenFactory;

    @Autowired
    @Qualifier("oidcPrincipalFactory")
    PrincipalFactory principalFactory;

    @Autowired
    ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory;

    @Autowired
    OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter;

    @Autowired
    CasConfigurationProperties casProperties;

    @Autowired
    CookieRetrievingCookieGenerator cookieGenerator;

    @Autowired
    OAuth20UserProfileViewRenderer userProfileViewRenderer;

    @Autowired
    OAuth20UserProfileDataCreator userProfileDataCreator;

    OAuth20UserProfileEndpointController oAuth20UserProfileEndpointController;

    MockHttpServletRequest request;
    MockHttpServletResponse response;

    @Before
    public void setUp() {
        oAuth20UserProfileEndpointController = initOAuth20UserProfileEndpointControllerWithMocks();

        Mockito.reset(ticketRegistry);

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void noAccessToken() throws Exception {
        ResponseEntity<String> httpResponse = oAuth20UserProfileEndpointController.handleRequest(request, response);
        Assert.assertEquals(HttpStatus.BAD_REQUEST, httpResponse.getStatusCode());
        Assert.assertTrue(HttpHeaders.WWW_AUTHENTICATE + " header was not found!",httpResponse.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE));
        Assert.assertEquals("Bearer error=\"invalid_request\",error_description=\"Missing access token from the request\"",httpResponse.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE).get(0));
    }

    @Test
    public void accessTokenExpired() throws Exception {
        request.addHeader(HttpConstants.AUTHORIZATION_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "mockAccessToken129");
        AccessToken accessToken = getMockAccessToken();
        ((AccessTokenImpl) accessToken).setExpired(true);
        mockTicketRegistryResponse(accessToken);

        ResponseEntity<String> httpResponse = oAuth20UserProfileEndpointController.handleRequest(request, response);
        Assert.assertEquals(HttpStatus.UNAUTHORIZED, httpResponse.getStatusCode());
        Assert.assertTrue(HttpHeaders.WWW_AUTHENTICATE + " header was not found!",httpResponse.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE));
        Assert.assertEquals("Bearer error=\"invalid_token\",error_description=\"The access token has expired\"",httpResponse.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE).get(0));
    }

    @Test
    public void accessTokenExpiredWhenNoAccessTokenFound() throws Exception {
        request.addHeader(HttpConstants.AUTHORIZATION_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "mockAccessToken129");
        mockTicketRegistryResponse(null);

        ResponseEntity<String> httpResponse = oAuth20UserProfileEndpointController.handleRequest(request, response);
        Assert.assertEquals(HttpStatus.UNAUTHORIZED, httpResponse.getStatusCode());
        Assert.assertTrue(HttpHeaders.WWW_AUTHENTICATE + " header was not found!",httpResponse.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE));
        Assert.assertEquals("Bearer error=\"invalid_token\",error_description=\"The access token has expired\"",httpResponse.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE).get(0));
    }

    @Test
    public void returnProfileWithValidTokenInHeader() throws Exception {
        request.addHeader(HttpConstants.AUTHORIZATION_HEADER, HttpConstants.BEARER_HEADER_PREFIX + MOCK_ACCESS_TOKEN);
        AccessToken accessToken = getMockAccessToken();
        mockTicketRegistryResponse(accessToken);

        ResponseEntity<String> httpResponse = oAuth20UserProfileEndpointController.handleRequest(request, response);

        Assert.assertEquals(HttpStatus.OK, httpResponse.getStatusCode());
        Assert.assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getHeader(HttpHeaders.CONTENT_TYPE));
        Mockito.verify(ticketRegistry).updateTicket(Mockito.eq(accessToken));
    }

    @Test
    public void returnProfileWithValidTokenInUrlParameter() throws Exception {
        request.addParameter("access_token", MOCK_ACCESS_TOKEN);
        AccessToken accessToken = getMockAccessToken();
        mockTicketRegistryResponse(accessToken);

        ResponseEntity<String> httpResponse = oAuth20UserProfileEndpointController.handleRequest(request, response);
        Assert.assertEquals(HttpStatus.OK, httpResponse.getStatusCode());
        Assert.assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getHeader(HttpHeaders.CONTENT_TYPE));
        Mockito.verify(ticketRegistry).updateTicket(Mockito.eq(accessToken));
    }

    private AccessTokenImpl getMockAccessToken() {
        return new AccessTokenImpl("AT-1", new SimpleWebApplicationServiceImpl(), MockPrincipalUtils.getMockBasicAuthentication(), new NeverExpiresExpirationPolicy(), MockPrincipalUtils.getMockUserAuthentication(MockPrincipalUtils.getMockEidasAuthPrincipalAttributes()), new ArrayList<>());
    }

    private void mockTicketRegistryResponse(AccessToken accessToken) {
        Mockito.when(ticketRegistry.getTicket(Mockito.eq(MOCK_ACCESS_TOKEN), Mockito.eq(AccessToken.class))).thenReturn(accessToken);
    }

    private OAuth20UserProfileEndpointController initOAuth20UserProfileEndpointControllerWithMocks() {
        return new OAuth20UserProfileEndpointController(servicesManager, ticketRegistry,
                accessTokenFactory, principalFactory, webApplicationServiceServiceFactory, scopeToAttributesFilter,
                casProperties, cookieGenerator, userProfileViewRenderer, userProfileDataCreator
        );
    }
}
