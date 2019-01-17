package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.oidc.OidcAuthorizeRequestValidationServletFilter;
import ee.ria.sso.oidc.OidcAuthorizeRequestParameter;
import ee.ria.sso.oidc.OidcAuthorizeRequestValidator;
import ee.ria.sso.oidc.TaraScope;
import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RunWith(SpringJUnit4ClassRunner.class)
public class OidcAuthorizeRequestValidationServletFilterTest {

    public static final String MOCK_REDIRECT_URI = "https://example.com:1234/oauth/response";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private OidcAuthorizeRequestValidator oidcRequestValidator;

    private OidcAuthorizeRequestValidationServletFilter servletFilter;

    @Before
    public void setUp() throws Exception {
        new ApplicationContextProvider().setApplicationContext(applicationContext);
        Mockito.when(applicationContext.getBean(Mockito.eq("oidcAuthorizeRequestValidator"), Mockito.any(Class.class))).thenReturn(oidcRequestValidator);
        servletFilter = new OidcAuthorizeRequestValidationServletFilter();
        servletFilter.init(Mockito.mock(FilterConfig.class));
    }

    @Test
    public void doFilterShouldExecuteWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servletFilter.doFilter(new MockHttpServletRequest(), servletResponse, Mockito.mock(FilterChain.class));
        Assert.assertEquals(200, servletResponse.getStatus());
    }

    @Test
    public void throwTechnicalExceptionWhenRedirectUriCannotBeDetermined() throws IOException, ServletException {
        assertExceptionThrownWhenParameterValidationFails(OidcAuthorizeRequestParameter.CLIENT_ID, OidcAuthorizeRequestParameter.REDIRECT_URI);
    }

    @Test
    public void assertRedirectWhenParameterValidationFails() throws IOException, ServletException {
        OidcAuthorizeRequestParameter[] parameters = getAllParametersExcept(OidcAuthorizeRequestParameter.CLIENT_ID, OidcAuthorizeRequestParameter.REDIRECT_URI);
        assertRedirectWhenParameterValidationFails(MOCK_REDIRECT_URI, "?" , parameters);
    }

    @Test
    public void assertRedirectWhenParameterValidationFailsAndRedirectUriContainsQueryPart() throws IOException, ServletException {
        OidcAuthorizeRequestParameter[] parameters = getAllParametersExcept(OidcAuthorizeRequestParameter.CLIENT_ID, OidcAuthorizeRequestParameter.REDIRECT_URI);
        assertRedirectWhenParameterValidationFails(MOCK_REDIRECT_URI + "?param=true", "&", parameters);
    }

    @Test
    public void assertProvidedScopesInSessionWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(),
                Arrays.stream(TaraScope.values()).map(s -> s.getFormalName()).collect(Collectors.joining(" "))
        );

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(Arrays.asList(TaraScope.values()),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPES)
        );
    }

    @Test
    public void assertClientIdInSessionWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.CLIENT_ID.getParameterKey(), "clientIdValue");

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals("clientIdValue", request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID));
    }

    @Test
    public void assertRedirectUriInSessionWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey(), "redirectUriValue");

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals("redirectUriValue", request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI));
    }

    @Test
    public void assertLoaInSessionWhenValidationSucceedsAndAcrValuesProvided() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey(),
                LevelOfAssurance.SUBSTANTIAL.getAcrName());

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(LevelOfAssurance.SUBSTANTIAL,
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LoA));
    }

    @Test
    public void assertLoaNotInSessionWhenValidationSucceedsAndAcrValuesNotProvided() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LoA));
    }

    @Test
    public void assertAllAuthMethodsInSessionWhenValidationSucceedsAndOnlyOpenidScopeProvided() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(),
                TaraScope.OPENID.getFormalName()
        );

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(
                Arrays.asList(AuthenticationType.values()).stream().filter(at -> at != AuthenticationType.Default).collect(Collectors.toList()),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS)
        );
    }

    @Test
    public void assertOnlyEidasAuthMethodInSessionWhenValidationSucceedsAndEidasonlyScopeProvided() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(),
                Arrays.asList(TaraScope.OPENID, TaraScope.EIDASONLY).stream()
                        .map(s -> s.getFormalName()).collect(Collectors.joining(" "))
        );

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(Arrays.asList(AuthenticationType.eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS)
        );
    }

    private void assertExceptionThrownWhenParameterValidationFails(OidcAuthorizeRequestParameter... parameters) throws IOException, ServletException {
        for (OidcAuthorizeRequestParameter parameter : parameters) {
            Mockito.doThrow(new OidcAuthorizeRequestValidator.InvalidRequestException(parameter, "test", "test description")).when(oidcRequestValidator).validateAuthenticationRequestParameters(Mockito.any());

            expectedEx.expect(IllegalStateException.class);
            expectedEx.expectMessage("Invalid authorization request, cannot redirect");

            servletFilter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        }
    }

    private void assertRedirectWhenParameterValidationFails(String redirectUri, String expectedDelimiter, OidcAuthorizeRequestParameter... parameters) throws IOException, ServletException {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addParameter("redirect_uri", redirectUri);
        servletRequest.addParameter("state", "123456789abcdefghjiklmn");

        for (OidcAuthorizeRequestParameter parameter : parameters) {
            Mockito.doThrow(new OidcAuthorizeRequestValidator.InvalidRequestException(parameter, "test", "test description")).when(oidcRequestValidator).validateAuthenticationRequestParameters(Mockito.any());

            MockHttpServletResponse servletResponse = new MockHttpServletResponse();
            servletFilter.doFilter(servletRequest, servletResponse, Mockito.mock(FilterChain.class));

            Assert.assertEquals(302, servletResponse.getStatus());
            Assert.assertEquals(redirectUri + expectedDelimiter + "error=test&error_description=test+description&state=123456789abcdefghjiklmn", servletResponse.getRedirectedUrl());
        }
    }

    private OidcAuthorizeRequestParameter[] getAllParametersExcept(OidcAuthorizeRequestParameter... parametersToBeExcluded) {
        List<OidcAuthorizeRequestParameter> parameters = new ArrayList<OidcAuthorizeRequestParameter>(Arrays.asList(OidcAuthorizeRequestParameter.values()));
        parameters.removeAll(Arrays.asList(parametersToBeExcluded));
        return parameters.toArray(new OidcAuthorizeRequestParameter[parameters.size()]);
    }

    @After
    public void tearDown() {
        servletFilter.destroy();
    }
}
