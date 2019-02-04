package ee.ria.sso.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import ee.ria.sso.AbstractTest;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.DefaultAuthentication;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegexRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.oidc.profile.OidcProfile;
import org.skyscreamer.jsonassert.Customization;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.skyscreamer.jsonassert.comparator.CustomComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.*;
import static ee.ria.sso.oidc.TaraOidcIdTokenGeneratorService.GENERATED_AND_ENCODED_ID_TOKEN_STRING;

@Slf4j
@RunWith(SpringJUnit4ClassRunner.class)
public class TaraOidcIdTokenGeneratorServiceTest extends AbstractTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    CasConfigurationProperties casProperties;

    @Autowired
    OidcIdTokenSigningAndEncryptionService signingService;

    @Mock
    ServicesManager servicesManager;

    @Mock
    AccessToken accessToken;

    @Mock
    OidcRegisteredService oidcRegisteredService;

    TaraOidcIdTokenGeneratorService taraOidcIdTokenGeneratorService;

    MockHttpServletRequest request;
    MockHttpServletResponse response;

    @Before
    public void setUp(){
        taraOidcIdTokenGeneratorService = new TaraOidcIdTokenGeneratorService(casProperties, signingService, servicesManager);

        Mockito.when(accessToken.getAuthentication()).thenReturn(getMockBasicAuthentication());
        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(getMockUserAuthentication(getMockMidAuthPrincipalAttributes()));
        Mockito.when(accessToken.getId()).thenReturn("accessTokenID");
        Mockito.when(oidcRegisteredService.isSignIdToken()).thenReturn(true);
        Mockito.when(oidcRegisteredService.getClientId()).thenReturn("openIdDemo");

        response = new MockHttpServletResponse();
        request = new MockHttpServletRequest();
        request.setSession(getMockSession());
    }

    @Test
    public void failGenerateWhenNotOidcRegisteredService() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Registered service instance is not an OIDC service");
        taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, new OAuthRegisteredService());
    }

    @Test
    public void failGenerateWhenNoAuthenticationProfilePresentInSession() {
        MockHttpSession session = getMockSession();
        session.setAttribute(Pac4jConstants.USER_PROFILES, new ArrayList<>());
        request.setSession(session);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Unable to determine the user profile from the context");
        taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService);
    }

    @Test
    public void successfulTokenGenerationIdCard() throws Exception {

        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(getMockUserAuthentication(getMockIdCardAuthPrincipalAttributes()));

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"openIdDemo\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"EE47101010033\"," +
                "\"profile_attributes\":{\"family_name\":\"Family-Name-ŠÕäÖü\",\"given_name\":\"Given-Name-ŠÕäÖü\",\"date_of_birth\":\"1971-01-01\",\"email\":\"givenname.familyname@eesti.ee\",\"email_verified\":false}," +
                "\"amr\":[\"idcard\"]," +
                "\"state\":\"state123abc\"," +
                "\"nonce\":\"1234567890nonce\"," +
                "\"at_hash\":\"fzJWdj0Xhq8b62dU7qGx9g==\"}", encodedToken);
    }

    @Test
    public void successfulTokenGenerationMid() throws Exception {

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"openIdDemo\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"EE47101010033\"," +
                "\"profile_attributes\":{\"family_name\":\"Family-Name-ŠÕäÖü\",\"given_name\":\"Given-Name-ŠÕäÖü\",\"date_of_birth\":\"1971-01-01\"}," +
                "\"amr\":[\"mID\"]," +
                "\"state\":\"state123abc\"," +
                "\"nonce\":\"1234567890nonce\"," +
                "\"at_hash\":\"fzJWdj0Xhq8b62dU7qGx9g==\"}", encodedToken);
    }

    @Test
    public void successfulTokenGenerationEidas() throws Exception {

        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(getMockUserAuthentication(getMockEidasAuthPrincipalAttributes()));

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"openIdDemo\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"GR1234567890-abcdefge78789768\"," +
                "\"profile_attributes\":{\"family_name\":\"Ωνάσης\",\"given_name\":\"Αλέξανδρος\",\"date_of_birth\":\"1980-01-01\"}," +
                "\"amr\":[\"eIDAS\"]," +
                "\"acr\":\"high\"," +
                "\"state\":\"state123abc\"," +
                "\"nonce\":\"1234567890nonce\"," +
                "\"at_hash\":\"fzJWdj0Xhq8b62dU7qGx9g==\"}", encodedToken);
    }

    private void verifyRequestAttributes(MockHttpServletRequest request, String encodedToken) {
        Assert.assertEquals("encoded token must also be set as a request parameter!", encodedToken, request.getAttribute(GENERATED_AND_ENCODED_ID_TOKEN_STRING));
    }

    private void verifyToken(String expectedStr, String encodedToken) throws Exception {
        Assert.assertNotNull("encoded token cannot be null!", encodedToken);
        Assert.assertTrue("encoded token is not in the correct format!", encodedToken.split("\\.").length == 3);
        log.debug("token: " + encodedToken);
        JWT jwt = JWTParser.parse(encodedToken);
        Assert.assertEquals("{\"alg\":\"RS256\"}", jwt.getHeader().toString());
        JSONAssert.assertEquals(
            expectedStr,
            jwt.getJWTClaimsSet().toString(),
                new CustomComparator(JSONCompareMode.NON_EXTENSIBLE,
                    new Customization("jti", (o1, o2) -> true),
                    new Customization("exp", (o1, o2) -> true),
                    new Customization("iat", (o1, o2) -> true),
                    new Customization("nbf", (o1, o2) -> true)
                )
        );
    }

    private MockHttpSession getMockSession() {
        MockHttpSession session = new MockHttpSession();
        OidcProfile profile = new OidcProfile();
        profile.setClientName("openIdDemo");
        session.setAttribute(Pac4jConstants.USER_PROFILES, profile);
        return session;
    }

    private TicketGrantingTicketImpl getMockUserAuthentication(Map<String, Object> attributes) {
        Principal taraPrincipal = new DefaultPrincipalFactory().createPrincipal("taraPrincipalId", attributes);
        DefaultAuthentication userAuthentication = new DefaultAuthentication(ZonedDateTime.of(2018, 1, 1,23,59,00,1, ZoneId.systemDefault()), taraPrincipal, new HashMap<>(), new HashMap<>());
        return new TicketGrantingTicketImpl("123", userAuthentication, Mockito.mock(ExpirationPolicy.class));
    }

    private DefaultAuthentication getMockBasicAuthentication() {
        Principal principal = new DefaultPrincipalFactory().createPrincipal("EE47101010033");
        HashMap<String, Object> attributes = new HashMap<>();
        attributes.put(OAuth20Constants.STATE, "state123abc");
        attributes.put(OAuth20Constants.NONCE, "1234567890nonce");
        return new DefaultAuthentication(ZonedDateTime.now(ZoneId.systemDefault()), principal, attributes, new HashMap<>());
    }

    private HashMap<String, Object> getMockMidAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(PRINCIPAL_CODE.name(), Arrays.asList("EE47101010033"));
        map.put(GIVEN_NAME.name(), Arrays.asList("Given-Name-ŠÕäÖü"));
        map.put(FAMILY_NAME.name(), Arrays.asList("Family-Name-ŠÕäÖü"));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList("1971-01-01"));
        map.put(AUTHENTICATION_TYPE.name(), Arrays.asList(AuthenticationType.MobileID.getAmrName()));
        return map;
    }

    private HashMap<String, Object> getMockIdCardAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(PRINCIPAL_CODE.name(), Arrays.asList("EE47101010033"));
        map.put(GIVEN_NAME.name(), Arrays.asList("Given-Name-ŠÕäÖü"));
        map.put(FAMILY_NAME.name(), Arrays.asList("Family-Name-ŠÕäÖü"));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList("1971-01-01"));
        map.put(EMAIL.name(), Arrays.asList("givenname.familyname@eesti.ee"));
        map.put(EMAIL_VERIFIED.name(), Arrays.asList(false));
        map.put(AUTHENTICATION_TYPE.name(), Arrays.asList(AuthenticationType.IDCard.getAmrName()));
        return map;
    }

    private HashMap<String, Object> getMockEidasAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(PRINCIPAL_CODE.name(), Arrays.asList("GR1234567890-abcdefge78789768"));
        map.put(GIVEN_NAME.name(), Arrays.asList("Αλέξανδρος"));
        map.put(FAMILY_NAME.name(), Arrays.asList("Ωνάσης"));
        map.put(AUTHENTICATION_TYPE.name(), Arrays.asList(AuthenticationType.eIDAS.getAmrName()));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList("1980-01-01"));
        map.put(LEVEL_OF_ASSURANCE.name(), Arrays.asList(LevelOfAssurance.HIGH.getAcrName()));
        return map;
    }

}
