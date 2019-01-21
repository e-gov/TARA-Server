package org.apereo.cas.oidc.web;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.config.TaraProperties;
import org.apereo.cas.authentication.DefaultAuthentication;
import org.apereo.cas.oidc.util.OidcAuthorizationRequestSupport;
import org.apereo.cas.util.Pac4jUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.oauth.profile.OAuth20Profile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public class OidcSecurityInterceptorTest extends AbstractTest {

    public static final String AUTHENTICATED_PROFILE_EXAMPLE = "authenticatedProfileExample";
    OidcSecurityInterceptor oidcSecurityInterceptor;

    @Autowired
    TaraProperties taraProperties;

    @Autowired
    @Qualifier("oauthSecConfig")
    private Config oauthSecConfig;

    @Autowired
    OidcAuthorizationRequestSupport authorizationRequestSupport;

    MockHttpServletRequest request;
    MockHttpServletResponse response;

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        Mockito.when(authorizationRequestSupport.isCasAuthenticationAvailable(Mockito.any())).thenReturn(Optional.of(new DefaultAuthentication()));
        oidcSecurityInterceptor = new OidcSecurityInterceptor(taraProperties, oauthSecConfig, "doesnotmatter", authorizationRequestSupport);
        Clients clients = getClients();
        Mockito.when(oauthSecConfig.getClients()).thenReturn(clients);
    }

    @Test
    public void whenForcedAuthEnabledAndAuthenticationProfilePresentAndVisitCountSetThenClearAuthProfiles() throws Exception {
        Mockito.when(taraProperties.isForceOidcAuthenticationRenewalEnabled()).thenReturn(true);
        J2EContext ctx = getMockRequestContext(getMockListOfAuthenticatedProfiles(), 1);

        oidcSecurityInterceptor.preHandle(request, response, null);

        verifyVisitCountCleared(ctx);
        verifyAuthenticationProfilesCleared(ctx);
    }

    @Test
    public void whenForcedAuthEnabledAndAuthProfilesPresentAndNoCountSetThenIncreaseCounter() throws Exception {
        Mockito.when(taraProperties.isForceOidcAuthenticationRenewalEnabled()).thenReturn(true);
        J2EContext ctx = getMockRequestContext(getMockListOfAuthenticatedProfiles(), null);

        oidcSecurityInterceptor.preHandle(request, response, null);

        verifyVisitCountSetTo(ctx, 1);
        verifyAuthenticationProfilesExist(ctx);
    }

    @Test
    public void whenForcedAuthDisabledThenIncreaseVisitCountAndDoNotClearAuthenticationProfile() throws Exception {
        Mockito.when(taraProperties.isForceOidcAuthenticationRenewalEnabled()).thenReturn(false);
        J2EContext ctx = getMockRequestContext(getMockListOfAuthenticatedProfiles(), null);

        oidcSecurityInterceptor.preHandle(request, response, null);
        oidcSecurityInterceptor.preHandle(request, response, null);
        oidcSecurityInterceptor.preHandle(request, response, null);
        oidcSecurityInterceptor.preHandle(request, response, null);

        verifyVisitCountSetTo(ctx, 4);
        verifyAuthenticationProfilesExist(ctx);
    }

    private void verifyVisitCountSetTo(J2EContext ctx, int i) {
        Assert.assertEquals(i, ctx.getSessionStore().get(ctx, OidcSecurityInterceptor.OIDC_AUTHORIZE_VISIT_COUNT));
    }

    private void verifyVisitCountCleared(J2EContext ctx) {
        Assert.assertEquals(null, ctx.getSessionStore().get(ctx, OidcSecurityInterceptor.OIDC_AUTHORIZE_VISIT_COUNT));
    }

    private void verifyAuthenticationProfilesExist(J2EContext ctx) {
        Assert.assertNotNull(ctx.getSessionStore().get(ctx, Pac4jConstants.USER_PROFILES));
        Assert.assertNotNull(((Map)ctx.getSessionStore().get(ctx, Pac4jConstants.USER_PROFILES)).get(AUTHENTICATED_PROFILE_EXAMPLE));
    }

    private void verifyAuthenticationProfilesCleared(J2EContext ctx) {
        Assert.assertNotNull(ctx.getSessionStore().get(ctx, Pac4jConstants.USER_PROFILES));
        Assert.assertTrue(((Map)ctx.getSessionStore().get(ctx, Pac4jConstants.USER_PROFILES)).isEmpty());
    }

    private J2EContext getMockRequestContext(LinkedHashMap<String, OAuth20Profile> authenticatedProfiles, Integer visitCount) {
        final J2EContext ctx = Pac4jUtils.getPac4jJ2EContext(request, response);
        ctx.getSessionStore().set(ctx, Pac4jConstants.USER_PROFILES, authenticatedProfiles);
        ctx.setRequestAttribute(Pac4jConstants.USER_PROFILES, authenticatedProfiles);
        ctx.getSessionStore().set(ctx, OidcSecurityInterceptor.OIDC_AUTHORIZE_VISIT_COUNT, visitCount);
        return ctx;
    }

    private LinkedHashMap<String, OAuth20Profile> getMockListOfAuthenticatedProfiles() {
        LinkedHashMap<String, OAuth20Profile> authenticatedProfiles = new LinkedHashMap<String, OAuth20Profile>();
        authenticatedProfiles.put(AUTHENTICATED_PROFILE_EXAMPLE, new OAuth20Profile());
        return authenticatedProfiles;
    }

    private Clients getClients() {
        Clients clients = new Clients();
        clients.setClients(getClient());
        return clients;
    }

    private Client getClient() {
        Client client = new CasClient(getConfiguration());
        ((CasClient) client).setName("doesnotmatter");
        ((CasClient) client).setCallbackUrl("http://callbackurl");
        return client;
    }

    private CasConfiguration getConfiguration() {
        CasConfiguration conf = new CasConfiguration();
        conf.setLoginUrl("http://login.url");
        conf.setRestUrl("http://rest.url");
        conf.setPrefixUrl("http://prefix.url");
        return conf;
    }
}
