package org.apereo.cas.oidc.token;

import ee.ria.sso.CommonConstants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.authentication.LevelOfAssurance;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.*;

public class OidcIdTokenGeneratorServiceTest {

    private static final String MOCK_CLIENT_ID = "someClientId";
    private static final String MOCK_ISSUER_NAME = "someIssuerName";
    private static final int MOCK_SKEW = 10;

    private static final String MOCK_OAUTH_STATE = "someOauthState";
    private static final String MOCK_OAUTH_NONCE = "someOauthNonce";

    private OidcIdTokenSigningAndEncryptionService signingService;
    private OidcIdTokenGeneratorService idTokenGeneratorService;

    @Before
    public void setUp() {
        signingService = Mockito.mock(OidcIdTokenSigningAndEncryptionService.class);
        Mockito.when(signingService.getJsonWebKeySigningAlgorithm()).thenReturn(AlgorithmIdentifiers.RSA_USING_SHA256);
        idTokenGeneratorService = new OidcIdTokenGeneratorService(MOCK_ISSUER_NAME, MOCK_SKEW, signingService);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithIdCardAttributes() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.IDCard, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.IDCard.getAmrName()
        ), null);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithMobileIdAttributes() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.MobileID, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);
        mapMobileNumber("87654321", expectedProfileAttributes, principalAttributes);

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.MobileID.getAmrName()
        ), null);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithEidasAttributes() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.eIDAS, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);
        mapDateOfBirth("2018-08-22", expectedProfileAttributes, principalAttributes);

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.eIDAS.getAmrName()
        ), null);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithEidasAttributesAndLoa() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.eIDAS, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);
        mapDateOfBirth("2018-08-22", expectedProfileAttributes, principalAttributes);
        principalAttributes.put("levelOfAssurance", LevelOfAssurance.SUBSTANTIAL.getAcrName());

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.eIDAS.getAmrName()
        ), LevelOfAssurance.SUBSTANTIAL.getAcrName());
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithBanklinkAttributes() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.BankLink, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);
        principalAttributes.put("banklinkType", BankEnum.SEB.getName().toUpperCase());

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.BankLink.getAmrName(), BankEnum.SEB.getName().toUpperCase()
        ), null);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithSmartIdAttributes() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.SmartID, principalAttributes);
        String identifier = mapPrincipalCode("abcd1234", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.SmartID.getAmrName()
        ), null);
    }

    @Test
    public void produceIdTokenClaimsShouldSucceedWithEstonianIdCodeAndNoDateOfBirth() throws MalformedClaimException {
        Map<String, Object> expectedProfileAttributes = new HashMap<>();
        Map<String, Object> principalAttributes = new HashMap<>();

        mapAuthenticationType(AuthenticationType.IDCard, principalAttributes);
        String identifier = mapPrincipalCode("EE51808220000", principalAttributes);
        mapFirstName("SomeFirstName", expectedProfileAttributes, principalAttributes);
        mapLastName("SomeLastName", expectedProfileAttributes, principalAttributes);
        mapDateOfBirth("2018-08-22", expectedProfileAttributes, null);

        JwtClaims jwtClaims = callProduceIdTokenClaims(mockAuthentication(
                createDefaultAuthenticationAttributesMap(), mockPrincipal(identifier, principalAttributes)
        ));
        verifyJwtClaims(jwtClaims, identifier, expectedProfileAttributes, Arrays.asList(
                AuthenticationType.IDCard.getAmrName()
        ), null);
    }

    private void verifyJwtClaims(JwtClaims claims, String subject, Map<String, Object> expectedProfileAttributes, List<String> expectedAmrValues, String acrValue) throws MalformedClaimException {
        Assert.assertNotNull("JwtClaims cannot be null!", claims);

        Assert.assertTrue(claims.getJwtId().matches(CommonConstants.UUID_REGEX));
        Assert.assertEquals(MOCK_ISSUER_NAME, claims.getIssuer());
        Assert.assertEquals(Arrays.asList(MOCK_CLIENT_ID), claims.getAudience());

        NumericDate currentTime = NumericDate.now();
        Assert.assertTrue("ExpirationTime cannot be in the past!", claims.getExpirationTime().isOnOrAfter(currentTime));
        Assert.assertTrue("IssuedAt cannot be in the future!", !claims.getIssuedAt().isAfter(currentTime));
        Assert.assertTrue("NotBefore cannot be after IssuedAt!", !claims.getNotBefore().isAfter(claims.getIssuedAt()));

        Assert.assertEquals(subject, claims.getSubject());
        Map<String, Object> profileAttributes = (Map<String, Object>) claims.getClaimValue("profile_attributes");
        Assert.assertEquals(expectedProfileAttributes.entrySet(), profileAttributes.entrySet());
        Assert.assertEquals(expectedAmrValues, claims.getClaimValue(OidcConstants.AMR));

        if (acrValue != null) {
            Assert.assertEquals(acrValue, claims.getClaimValue(OidcConstants.ACR));
        }

        Assert.assertEquals(MOCK_OAUTH_STATE, claims.getClaimValue(OAuth20Constants.STATE));
        Assert.assertEquals(MOCK_OAUTH_NONCE, claims.getClaimValue(OAuth20Constants.NONCE));
        Assert.assertEquals(generateHalfHashBase64(subject), claims.getClaimValue(OidcConstants.CLAIM_AT_HASH));

        Set<String> expectedClaimSet = new HashSet<>();
        Collections.addAll(expectedClaimSet, "jti", "iss", "aud", "exp", "iat", "nbf", "sub", "profile_attributes",
                OidcConstants.AMR, OAuth20Constants.STATE, OAuth20Constants.NONCE, OidcConstants.CLAIM_AT_HASH);
        if (acrValue != null) expectedClaimSet.add(OidcConstants.ACR);
        Assert.assertEquals(expectedClaimSet, claims.getClaimNames());
    }

    private JwtClaims callProduceIdTokenClaims(Authentication authentication) {
        AccessToken accessTokenId = mockAccessToken(authentication);

        OidcRegisteredService service = Mockito.mock(OidcRegisteredService.class);
        Mockito.when(service.getClientId()).thenReturn(MOCK_CLIENT_ID);

        return idTokenGeneratorService.produceIdTokenClaims(
                null,
                accessTokenId,
                1L,
                service,
                null,
                null,
                null
        );
    }

    private AccessToken mockAccessToken(Authentication authentication) {
        AccessToken accessToken = Mockito.mock(AccessToken.class);
        String id = authentication.getPrincipal().getId();

        Mockito.when(accessToken.getAuthentication()).thenReturn(authentication);
        Mockito.when(accessToken.getId()).thenReturn(id);

        return accessToken;
    }

    private Authentication mockAuthentication(Map<String, Object> attributes, Principal principal) {
        Authentication authentication = Mockito.mock(Authentication.class);
        Mockito.when(authentication.getAttributes()).thenReturn(attributes);
        Mockito.when(authentication.getPrincipal()).thenReturn(principal);
        return authentication;
    }

    private Principal mockPrincipal(String id, Map<String, Object> attributes) {
        Principal principal = Mockito.mock(Principal.class);

        Mockito.when(principal.getId()).thenReturn(id);
        Mockito.when(principal.getAttributes()).thenReturn(attributes);

        return principal;
    }

    private Map<String, Object> createDefaultAuthenticationAttributesMap() {
        Map<String, Object> authenticationAttributes = new HashMap<>();

        authenticationAttributes.put(AuthenticationHandler.SUCCESSFUL_AUTHENTICATION_HANDLERS, "TaraAuthenticationHandler");
        authenticationAttributes.put(OAuth20Constants.STATE, MOCK_OAUTH_STATE);
        authenticationAttributes.put(OAuth20Constants.NONCE, MOCK_OAUTH_NONCE);

        return authenticationAttributes;
    }

    private String generateHalfHashBase64(String input) {
        final byte[] tokenBytes = input.getBytes();
        final String hashAlg;

        switch (signingService.getJsonWebKeySigningAlgorithm()) {
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                hashAlg = MessageDigestAlgorithms.SHA_512;
                break;
            case AlgorithmIdentifiers.RSA_USING_SHA256:
            default:
                hashAlg = MessageDigestAlgorithms.SHA_256;
        }

        final byte[] digested = DigestUtils.rawDigest(hashAlg, tokenBytes);
        final byte[] hashBytesLeftHalf = Arrays.copyOf(digested, digested.length / 2);
        return EncodingUtils.encodeBase64(hashBytesLeftHalf);
    }

    private String mapAuthenticationType(AuthenticationType type, Map<String, Object> principalAttributes) {
        if (principalAttributes != null) principalAttributes.put("authenticationType", type.getAmrName());
        return type.getAmrName();
    }

    private String mapPrincipalCode(String principalCode, Map<String, Object> principalAttributes) {
        if (principalAttributes != null) principalAttributes.put("principalCode", principalCode);
        return principalCode;
    }

    private void mapFirstName(String firstName, Map<String, Object> expectedProfileAttributes, Map<String, Object> principalAttributes) {
        if (expectedProfileAttributes != null) expectedProfileAttributes.put("given_name", firstName);
        if (principalAttributes != null) principalAttributes.put("firstName", firstName);
    }

    private void mapLastName(String lastName, Map<String, Object> expectedProfileAttributes, Map<String, Object> principalAttributes) {
        if (expectedProfileAttributes != null) expectedProfileAttributes.put("family_name", lastName);
        if (principalAttributes != null) principalAttributes.put("lastName", lastName);
    }

    private void mapMobileNumber(String mobileNumber, Map<String, Object> expectedProfileAttributes, Map<String, Object> principalAttributes) {
        if (expectedProfileAttributes != null) expectedProfileAttributes.put("mobile_number", mobileNumber);
        if (principalAttributes != null) principalAttributes.put("mobileNumber", mobileNumber);
    }

    private void mapDateOfBirth(String dateOfBirth, Map<String, Object> expectedProfileAttributes, Map<String, Object> principalAttributes) {
        if (expectedProfileAttributes != null) expectedProfileAttributes.put("date_of_birth", dateOfBirth);
        if (principalAttributes != null) principalAttributes.put("dateOfBirth", dateOfBirth);
    }

}
