package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
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

import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class OidcAuthorizeRequestValidationServletFilterTest {

    public static final String MOCK_REDIRECT_URI = "https://example.com:1234/oauth/response";
    private static final List<String> ALLOWED_EIDAS_COUNTRY_ATTRIBUTES =
            Arrays.asList(scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "en"), scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "ru"));

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    private OidcAuthorizeRequestValidator oidcRequestValidator;

    @Mock
    private EidasConfigurationProvider eidasConfigurationProvider;

    private OidcAuthorizeRequestValidationServletFilter servletFilter;

    @Before
    public void setUp() {
        when(eidasConfigurationProvider.getAllowedEidasCountryScopeAttributes()).thenReturn(ALLOWED_EIDAS_COUNTRY_ATTRIBUTES);

        servletFilter = new OidcAuthorizeRequestValidationServletFilter(oidcRequestValidator, eidasConfigurationProvider);
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
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LOA));
    }

    @Test
    public void assertLoaNotInSessionWhenValidationSucceedsAndAcrValuesNotProvided() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LOA));
    }

    @Test
    public void assertAllAuthMethodsInSession() throws Exception {
        assertAllAuthMethodsInSession(TaraScope.OPENID.getFormalName());
        assertAllAuthMethodsInSession(String.join(" ", TaraScope.OPENID.getFormalName(), "unkonwn"));
        assertAllAuthMethodsInSession(String.join(" ", TaraScope.OPENID.getFormalName(), "IDCARD"));
        assertAllAuthMethodsInSession(String.join(" ", TaraScope.OPENID.getFormalName() ,
                TaraScope.IDCARD.getFormalName(),
                TaraScope.MID.getFormalName(),
                TaraScope.EIDAS.getFormalName(),
                TaraScope.BANKLINK.getFormalName(),
                TaraScope.SMARTID.getFormalName()));
    }

    @Test
    public void assertSingleAuthMethodsInSession() throws Exception {
        for (AuthenticationType authenticationType : Arrays.stream(AuthenticationType.values()).collect(Collectors.toList())) {

            String scope = authenticationType.getScope().getFormalName();

            assertAuthMethodInSession("Assert single scope",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope),
                    authenticationType
            );

            assertAuthMethodInSession("Assert invalid scope is ignored",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope, "unknown"),
                    authenticationType
            );

            assertAuthMethodInSession("Assert redundant scope is ignored",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope, scope),
                    authenticationType
            );
        }
    }

    @Test
    public void assertSelectionOfAuthMethodsInSession() throws Exception {
            AuthenticationType authenticationType1 = AuthenticationType.IDCard;
            AuthenticationType authenticationType2 = AuthenticationType.eIDAS;
            String scope1 = authenticationType1.getScope().getFormalName();
            String scope2 = authenticationType2.getScope().getFormalName();

            assertAuthMethodInSession("Assert single occurrence of valid scope",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope1, scope2),
                    authenticationType1,
                    authenticationType2
            );

            assertAuthMethodInSession("Assert invalid scope is ignored",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope1, "unknown", scope2),
                    authenticationType1,
                    authenticationType2
            );

            assertAuthMethodInSession("Assert redundant scope is ignored",
                    String.join(" ", TaraScope.OPENID.getFormalName(), scope1, scope1, scope2, scope2, scope2),
                    authenticationType1,
                    authenticationType2
            );
    }


    @Test
    public void assertAllAuthMethodsInSessionWhenValidationSucceedsAndOnlyOpenidScopeProvided() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(),
                TaraScope.OPENID.getFormalName()
        );

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(
                Arrays.asList(AuthenticationType.values()).stream().collect(Collectors.toList()),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS)
        );
    }



    @Test
    public void assertOnlyEidasAuthMethodInSessionWhenValidationSucceedsAndEidasonlyScopeProvided() throws Exception {
        assertAuthMethodInSession("Assert single occurrence of valid scope",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName()),
                AuthenticationType.eIDAS
        );

        assertAuthMethodInSession("Assert eidasonly overrides all other auth selection scopes",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), TaraScope.EIDAS.getFormalName()),
                AuthenticationType.eIDAS
        );

        assertAuthMethodInSession("Assert eidasonly overrides eidas",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), TaraScope.IDCARD.getFormalName()),
                AuthenticationType.eIDAS
        );
    }

    @Test
    public void assertScopeValuedAttributeEidasCountryParsedFromScope() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "en";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(AuthenticationType.eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertWhenMultipleEidasCountryPresentInScope_thenFirstIsTaken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "en";
        String eidasCountry2 = "ru";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String eidasCountryScopeAttribute2 = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry2);
        String scopeValue = String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(),
                eidasCountryScopeAttribute, eidasCountryScopeAttribute2);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(AuthenticationType.eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertScopeAndItsValuedAttributesOrderParsedFromScopeIsNotImportant() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "en";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", eidasCountryScopeAttribute, TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName());
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(AuthenticationType.eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertOnlyEidasCountryAttributeParsedFromScope() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "en";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method not read from request and default value initialized",
                Arrays.asList(AuthenticationType.values()),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertInvalidScopeValuedAttributeIsIgnored() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "en";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String invalidScopeAttribute = "invalid:scope:attribute:2";
        String scopeValue = String.join(" ", eidasCountryScopeAttribute, invalidScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertEidasCountryScopeAttributeWithoutValueIsIgnored() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "");
        String scopeValue = String.join(" ", eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY));
    }

    @Test
    public void assertEidasCountryScopeAttributeWithUppercaseValueIsIgnored() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "EN");
        String scopeValue = String.join(" ", eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY));
    }

    @Test
    public void assertEidasCountryThatIsNotAllowedIsIgnored() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "fi";
        Assert.assertFalse(ALLOWED_EIDAS_COUNTRY_ATTRIBUTES.contains(eidasCountry));
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY));
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
        servletRequest.addParameter("state", "123456789abcdefghjiklmn&additional=1");

        for (OidcAuthorizeRequestParameter parameter : parameters) {
            Mockito.doThrow(new OidcAuthorizeRequestValidator.InvalidRequestException(parameter, "test", "test description")).when(oidcRequestValidator).validateAuthenticationRequestParameters(Mockito.any());

            MockHttpServletResponse servletResponse = new MockHttpServletResponse();
            servletFilter.doFilter(servletRequest, servletResponse, Mockito.mock(FilterChain.class));

            Assert.assertEquals(302, servletResponse.getStatus());
            Assert.assertEquals(redirectUri + expectedDelimiter + "error=test&error_description=test+description&state=123456789abcdefghjiklmn%26additional%3D1", servletResponse.getRedirectedUrl());
        }
    }

    private OidcAuthorizeRequestParameter[] getAllParametersExcept(OidcAuthorizeRequestParameter... parametersToBeExcluded) {
        List<OidcAuthorizeRequestParameter> parameters = new ArrayList<OidcAuthorizeRequestParameter>(Arrays.asList(OidcAuthorizeRequestParameter.values()));
        parameters.removeAll(Arrays.asList(parametersToBeExcluded));
        return parameters.toArray(new OidcAuthorizeRequestParameter[parameters.size()]);
    }


    private void assertAllAuthMethodsInSession(String scopeValue) throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(
                Arrays.asList(AuthenticationType.values()).stream().collect(Collectors.toList()),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS)
        );
    }

    private void assertAuthMethodInSession(String message, String scopeValue, AuthenticationType... authMethodInSession) throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(message,
                Arrays.asList(authMethodInSession),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS)
        );
    }

    private static String scopeValuedAttribute(TaraScopeValuedAttributeName scopeAttributeName, String attributeValue) {
        return scopeAttributeName.getFormalName() + ":" + attributeValue;
    }

    private static void assertScopeAttribute(TaraScopeValuedAttribute scopeAttribute, TaraScopeValuedAttributeName scopeAttributeName, String scopeAttributeValue) {
        Assert.assertSame(scopeAttributeName, scopeAttribute.getName());
        Assert.assertEquals(scopeAttributeValue, scopeAttribute.getValue());
    }

    @After
    public void tearDown() {
        servletFilter.destroy();
    }
}
