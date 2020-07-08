package ee.ria.sso.oidc;

import com.google.common.collect.ImmutableMap;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import org.junit.*;
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

import static ee.ria.sso.authentication.AuthenticationType.*;
import static ee.ria.sso.authentication.LevelOfAssurance.*;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class OidcAuthorizeRequestValidationServletFilterTest {

    public static final String MOCK_REDIRECT_URI = "https://example.com:1234/oauth/response";
    private static final List<String> ALLOWED_EIDAS_COUNTRY_ATTRIBUTES =
            Arrays.asList(scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "gb"), scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "ru"));
    public static final ImmutableMap<AuthenticationType, LevelOfAssurance> DEFAULT_MAP_OF_EIDAS_ASSURANCE_LEVELS = ImmutableMap.of(
            IDCard, HIGH,
            MobileID, HIGH,
            BankLink, LOW,
            SmartID, SUBSTANTIAL
    );
    public static final AuthenticationType[] DEFAULT_LIST_OF_ENABLED_AUTH_METHODS = {IDCard, MobileID, BankLink, SmartID, eIDAS};

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    private OidcAuthorizeRequestValidator oidcRequestValidator;

    @Mock
    private EidasConfigurationProvider eidasConfigurationProvider;

    @Mock
    private TaraProperties taraProperties;

    private OidcAuthorizeRequestValidationServletFilter servletFilter;

    @Before
    public void setUp() {
        setAllowedEidasCountries(ALLOWED_EIDAS_COUNTRY_ATTRIBUTES);
        setAuthMethodEidasAssuranceLevels(DEFAULT_MAP_OF_EIDAS_ASSURANCE_LEVELS);
        setEnabledAuthMethods(DEFAULT_LIST_OF_ENABLED_AUTH_METHODS);
        setDefaultAuthMethodsList(DEFAULT_LIST_OF_ENABLED_AUTH_METHODS);

        servletFilter = new OidcAuthorizeRequestValidationServletFilter(oidcRequestValidator, eidasConfigurationProvider, taraProperties);
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
    public void assertStateInSessionWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.STATE.getParameterKey(), "stateValue");

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals("stateValue", request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_STATE));
    }

    @Test
    public void assertLoaInSessionWhenValidationSucceedsAndAcrValuesProvided() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey(),
                SUBSTANTIAL.getAcrName());

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(SUBSTANTIAL,
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LOA));
    }

    @Test
    public void assertLoaNotInSessionWhenValidationSucceedsAndAcrValuesNotProvided() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertNull(request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_LOA));
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
    public void assertRedirectWithErrorWhenAllAuthMethodsAreFilteredByLoa() throws Exception {
        setDefaultAuthMethodsList(new AuthenticationType[]{IDCard, SmartID});
        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(
                BankLink, LOW,
                SmartID, SUBSTANTIAL
        ));

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addParameter("scope", String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.SMARTID.getFormalName()), TaraScope.BANKLINK.getFormalName());
        servletRequest.addParameter("acr_values", HIGH.getAcrName());
        servletRequest.addParameter("redirect_uri", "https://example.redirect.uri:7866");
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        servletFilter.doFilter(servletRequest, servletResponse, Mockito.mock(FilterChain.class));

        Assert.assertEquals(302, servletResponse.getStatus());
        Assert.assertEquals("https://example.redirect.uri:7866?error=invalid_request&error_description=No+authentication+methods+match+the+requested+level+of+assurance.+Please+check+your+authorization+request", servletResponse.getRedirectedUrl());

    }

    @Test
    public void assertDomesticAuthMethodsInSessionAreFilteredByLoa() throws Exception {

        // more than one > filter out the authmethods with insufficient loa level
        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(IDCard, HIGH,
                SmartID, SUBSTANTIAL));
        setDefaultAuthMethodsList(new AuthenticationType[]{IDCard, SmartID});
        assertAuthMethodInSession("Assert auth method IS NOT returned when the expected loa is higher than auth method loa",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.SMARTID.getFormalName(), TaraScope.IDCARD.getFormalName()),
                HIGH.getAcrName(),
                IDCard
        );

        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(SmartID, HIGH));
        assertAuthMethodInSession("Assert auth method returned when the expected loa and auth method loa match",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.SMARTID.getFormalName()),
                HIGH.getAcrName(),
                SmartID
        );

        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(SmartID, HIGH));
        assertAuthMethodInSession("Assert auth method returned when the expected loa is lower than auth method loa",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.SMARTID.getFormalName()),
                SUBSTANTIAL.getAcrName(),
                SmartID
        );

        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(SmartID, HIGH));
        setDefaultAuthMethodsList(new AuthenticationType[]{IDCard, MobileID, SmartID});
        assertAuthMethodInSession("Assert matching auth methods returned (methods with LoA assigned together with auth methods without LoA)",
                String.join(" ", TaraScope.OPENID.getFormalName()),
                SUBSTANTIAL.getAcrName(),
                IDCard, MobileID, SmartID
        );

        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(SmartID, HIGH));
        setDefaultAuthMethodsList(new AuthenticationType[]{SmartID});
        assertAuthMethodInSession("Assert auth method returned when the authentication method present in the default authentication methods list",
                String.join(" ", TaraScope.OPENID.getFormalName()),
                SUBSTANTIAL.getAcrName(),
                SmartID
        );
    }

    @Test
    public void assertEidasAuthMethodIsNotFilteredRegardlessOfAcrValue() throws Exception {

        // eidas method explicitly requested
        setAuthMethodEidasAssuranceLevels(ImmutableMap.of(
                IDCard, HIGH,
                SmartID, SUBSTANTIAL,
                BankLink, LOW
        ));
        setDefaultAuthMethodsList(new AuthenticationType[]{IDCard, SmartID, BankLink});
        for (LevelOfAssurance loa : LevelOfAssurance.values()) {

            assertAuthMethodInSession ("Assert eidas authentication method is returned with 'eidasonly' scope, regardless of acr_value - " + loa,
                    String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName()),
                    loa.getAcrName(),
                    eIDAS
            );

            assertAuthMethodInSession ("Assert eidas authentication method is returned with 'eidas' scope, regardless of acr_value - " + loa,
                    String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDAS.getFormalName()),
                    loa.getAcrName(),
                    eIDAS
            );
        }

        // eidas method from default authmethods list
        setDefaultAuthMethodsList(new AuthenticationType[]{eIDAS});
        for (LevelOfAssurance loa : LevelOfAssurance.values()) {
            assertAuthMethodInSession("Assert eidas authentication method is returned regardless of acr_value",
                    String.join(" ", TaraScope.OPENID.getFormalName()),
                    loa.getAcrName(),
                    eIDAS
            );
        }
    }

    @Test
    public void assertSelectionOfAuthMethodsInSession() throws Exception {
            AuthenticationType authenticationType1 = IDCard;
            AuthenticationType authenticationType2 = eIDAS;
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
    public void assertConfiguredListOfAuthMethodsInSessionWhenNoScopesProvided() throws Exception {

        // #1 auth-method scopes explicitly not requested, acr not requested, all-methods enabled (returns single default method)
        setDefaultAuthMethodsList(IDCard);
        assertAuthMethodInSession("Assert auth-methods list allowed when no scopes specified, no acr_values provided, with a single default value",
                "",
                IDCard
        );


        // #2 auth-method scopes explicitly not requested, acr not requested, all-methods enabled (returns sublist of default methods)
        setDefaultAuthMethodsList(IDCard, eIDAS);
        assertAuthMethodInSession("Assert auth-methods list allowed when no scopes specified, no acr_values provided, with a list of default values",
                String.join(" ", TaraScope.OPENID.getFormalName()),
                IDCard, eIDAS
        );
    }

    @Test
    public void assertConfiguredListOfAuthMethodsInSessionWhenOnlyNonAuthMethodScopesProvided() throws Exception {

        setDefaultAuthMethodsList(IDCard, eIDAS);
        assertAuthMethodInSession("Assert default auth methods allowed when not scopes specified",
                String.join(" ", "scope1", "scope2", "scope3"),
                IDCard, eIDAS
        );
    }

    @Test
    public void assertOnlyEidasAuthMethodInSessionWhenValidationSucceedsAndEidasonlyScopeProvided() throws Exception {
        assertAuthMethodInSession("Assert single occurrence of valid scope",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName()),
                eIDAS
        );

        assertAuthMethodInSession("Assert eidasonly overrides all other auth selection scopes",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), TaraScope.EIDAS.getFormalName()),
                eIDAS
        );

        assertAuthMethodInSession("Assert eidasonly overrides eidas",
                String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), TaraScope.IDCARD.getFormalName()),
                eIDAS
        );
    }

    @Test
    public void assertScopeValuedAttributeEidasCountryParsedFromScope() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "gb";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(), eidasCountryScopeAttribute);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertWhenMultipleEidasCountryPresentInScope_thenFirstIsTaken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "gb";
        String eidasCountry2 = "ru";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String eidasCountryScopeAttribute2 = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry2);
        String scopeValue = String.join(" ", TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName(),
                eidasCountryScopeAttribute, eidasCountryScopeAttribute2);
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertScopeAndItsValuedAttributesOrderParsedFromScopeIsNotImportant() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "gb";
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
        String scopeValue = String.join(" ", eidasCountryScopeAttribute, TaraScope.OPENID.getFormalName(), TaraScope.EIDASONLY.getFormalName());
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));

        Assert.assertEquals("Assert authentication method read from request",
                Arrays.asList(eIDAS),
                request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS));

        TaraScopeValuedAttribute scopeAttribute = (TaraScopeValuedAttribute) request.getSession(false).getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        assertScopeAttribute(scopeAttribute, TaraScopeValuedAttributeName.EIDAS_COUNTRY, eidasCountry);
    }

    @Test
    public void assertOnlyEidasCountryAttributeParsedFromScope() throws Exception {
        when(taraProperties.getDefaultAuthenticationMethods()).thenReturn(Arrays.asList(AuthenticationType.values()));

        MockHttpServletRequest request = new MockHttpServletRequest();
        String eidasCountry = "gb";
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
        String eidasCountry = "gb";
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
        String eidasCountryScopeAttribute = scopeValuedAttribute(TaraScopeValuedAttributeName.EIDAS_COUNTRY, "GB");
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

    private void assertAuthMethodInSession(String message, String scopeValue, AuthenticationType... allowedAuthMethods) throws IOException, ServletException {
        assertAuthMethodInSession(message, scopeValue, null, allowedAuthMethods);
    }

    private void assertAuthMethodInSession(String message, String scopeValue, String acrValues, AuthenticationType... allowedAuthMethods) throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey(), scopeValue);
        request.addParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey(), "https://mock.redirect.uri");
        if (acrValues != null) {
            request.addParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey(), acrValues);
        }

        servletFilter.doFilter(request, new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        Assert.assertEquals(message,
                Arrays.asList(allowedAuthMethods),
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


    private void setAuthMethodEidasAssuranceLevels(ImmutableMap<AuthenticationType, LevelOfAssurance> authMethodsAndLevelOfAssurances) {
        when(taraProperties.getAuthenticationMethodsLoaMap()).thenReturn(authMethodsAndLevelOfAssurances);
    }

    private void setDefaultAuthMethodsList(AuthenticationType... authMethods) {
        when(taraProperties.getDefaultAuthenticationMethods()).thenReturn(Arrays.asList(authMethods));
    }

    private void setEnabledAuthMethods(AuthenticationType... authMethods) {
        for (AuthenticationType authMethod : authMethods) {
            when(taraProperties.isPropertyEnabled(Mockito.eq(authMethod.getPropertyName()+ ".enabled"))).thenReturn(true);
        }
    }

    private void setAllowedEidasCountries(List<String> allowedEidasCountryAttributes) {
        when(eidasConfigurationProvider.getAllowedEidasCountryScopeAttributes()).thenReturn(allowedEidasCountryAttributes);
    }

    private AuthenticationType[] getConfiguredAuthMethodsWithLoa(LevelOfAssurance loa) {
        List<AuthenticationType> list = taraProperties.getAuthenticationMethodsLoaMap().entrySet().stream()
                .filter(x -> x.getValue().ordinal() >= loa.ordinal())
                .map( p -> p.getKey())
                .collect(Collectors.toList());

        list.add(eIDAS);
        return list.toArray(new AuthenticationType[list.size()]);
    }

    @After
    public void tearDown() {
        servletFilter.destroy();
    }
}
