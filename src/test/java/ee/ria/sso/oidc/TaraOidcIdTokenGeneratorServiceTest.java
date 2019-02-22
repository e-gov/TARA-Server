package ee.ria.sso.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import ee.ria.sso.AbstractTest;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
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

import java.util.ArrayList;

import static ee.ria.sso.oidc.TaraOidcIdTokenGeneratorService.GENERATED_AND_ENCODED_ID_TOKEN_STRING;

@Slf4j
@RunWith(SpringJUnit4ClassRunner.class)
public class TaraOidcIdTokenGeneratorServiceTest extends AbstractTest {

    public static final String MOCK_CLIENT_ID = "openIdDemo";
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

        Mockito.when(accessToken.getAuthentication()).thenReturn(MockPrincipalUtils.getMockBasicAuthentication());
        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(MockPrincipalUtils.getMockUserAuthentication(MockPrincipalUtils.getMockMidAuthPrincipalAttributes()));
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

        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(MockPrincipalUtils.getMockUserAuthentication(MockPrincipalUtils.getMockIdCardAuthPrincipalAttributes()));

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"" + MOCK_CLIENT_ID + "\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EE + "\"," +
                "\"email\":\"" + MockPrincipalUtils.MOCK_EMAIL + "\"," +
                "\"email_verified\":false," +
                "\"profile_attributes\":{\"family_name\":\"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\"given_name\":\"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\"date_of_birth\":\"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\"}," +
                "\"amr\":[\"" + AuthenticationType.IDCard.getAmrName() + "\"]," +
                "\"state\":\"" + MockPrincipalUtils.STATE + "\"," +
                "\"nonce\":\"" + MockPrincipalUtils.NONCE + "\"," +
                "\"at_hash\":\"fzJWdj0Xhq8b62dU7qGx9g==\"}", encodedToken);
    }

    @Test
    public void successfulTokenGenerationMid() throws Exception {

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"" + MOCK_CLIENT_ID + "\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EE + "\"," +
                "\"profile_attributes\":{\"family_name\":\"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\"given_name\":\"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\"date_of_birth\":\"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\"}," +
                "\"amr\":[\"" + AuthenticationType.MobileID.getAmrName() + "\"]," +
                "\"state\":\"" + MockPrincipalUtils.STATE + "\"," +
                "\"nonce\":\"" + MockPrincipalUtils.NONCE + "\"," +
                "\"at_hash\":\"fzJWdj0Xhq8b62dU7qGx9g==\"}", encodedToken);
    }

    @Test
    public void successfulTokenGenerationEidas() throws Exception {

        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(MockPrincipalUtils.getMockUserAuthentication(MockPrincipalUtils.getMockEidasAuthPrincipalAttributes()));

        String encodedToken = taraOidcIdTokenGeneratorService.generate(request, response, accessToken, 1, OAuth20ResponseTypes.CODE, oidcRegisteredService );
        verifyRequestAttributes(request, encodedToken);
        verifyToken("{\"jti\":\"e7767849-49e5-412d-9148-1099a3b3325f\"," +
                "\"iss\":\"http://localhost:8080/cas/oidc\"," +
                "\"aud\":\"" + MOCK_CLIENT_ID + "\"," +
                "\"exp\":1545337305," +
                "\"iat\":1545337304," +
                "\"nbf\":1545337004," +
                "\"sub\":\"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EIDAS + "\"," +
                "\"profile_attributes\":{\"family_name\":\"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\"given_name\":\"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\"date_of_birth\":\"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\"}," +
                "\"amr\":[\"" + AuthenticationType.eIDAS.getAmrName() + "\"]," +
                "\"acr\":\"" + LevelOfAssurance.HIGH.getAcrName() + "\"," +
                "\"state\":\"" + MockPrincipalUtils.STATE + "\"," +
                "\"nonce\":\"" + MockPrincipalUtils.NONCE + "\"," +
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
        profile.setClientName(MOCK_CLIENT_ID);
        session.setAttribute(Pac4jConstants.USER_PROFILES, profile);
        return session;
    }
}
