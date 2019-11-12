package ee.ria.sso.flow.action;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.oidc.TaraScopeValuedAttribute;
import ee.ria.sso.oidc.TaraScopeValuedAttributeName;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
public class InitializeLoginActionTest {

    @InjectMocks
    private InitializeLoginAction action;

    @Test
    public void scopeEidasOnlyAndScopeValuedAttributeEidasCountryPresent_thenDirectEidasLogin() {
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, Arrays.asList(TaraScope.OPENID, TaraScope.EIDASONLY));

        TaraScopeValuedAttribute eidasCountryAttribute = TaraScopeValuedAttribute.builder()
                .name(TaraScopeValuedAttributeName.EIDAS_COUNTRY)
                .value("gb")
                .build();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY, eidasCountryAttribute);

        Event event = action.doExecute(mockRequestContext(mockHttpSession));
        assertEquals("directEidasLogin", event.getId());
    }

    @Test
    public void scopeEidasOnlyButScopeAttributesMissing_thenShowLoginForm() {
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, Arrays.asList(TaraScope.OPENID, TaraScope.EIDASONLY));
        Event event = action.doExecute(mockRequestContext(mockHttpSession));
        assertEquals("loginForm", event.getId());
    }

    @Test
    public void scopeEidasOnlyButScopeAttributesEidasCountryMissing_thenShowLoginForm() {
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, Arrays.asList(TaraScope.OPENID, TaraScope.EIDASONLY));

        Event event = action.doExecute(mockRequestContext(mockHttpSession));
        assertEquals("loginForm", event.getId());
    }

    @Test
    public void eidasOnlyScopeMissingButScopeAttributeEidasCountryPresent_thenShowLoginForm() {
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, Arrays.asList(TaraScope.OPENID));

        TaraScopeValuedAttribute eidasCountryAttribute = TaraScopeValuedAttribute.builder()
                .name(TaraScopeValuedAttributeName.EIDAS_COUNTRY)
                .value("gb")
                .build();
        mockHttpSession.setAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY, eidasCountryAttribute);

        Event event = action.doExecute(mockRequestContext(mockHttpSession));
        assertEquals("loginForm", event.getId());
    }

    private RequestContext mockRequestContext(MockHttpSession mockHttpSession) {
        MockRequestContext requestContext = new MockRequestContext();
        MockExternalContext mockExternalContext = new MockExternalContext();
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setSession(mockHttpSession);
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
        requestContext.setExternalContext(mockExternalContext);
        requestContext.getFlowScope().put("credential", new PreAuthenticationCredential());
        return requestContext;
    }
}
