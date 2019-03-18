package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.principal.TaraPrincipal;
import ee.ria.sso.authentication.principal.TaraPrincipalFactory;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.token.OidcIdTokenGeneratorService;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.Pac4jUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.*;


@Slf4j
@Getter
public class TaraOidcIdTokenGeneratorService extends OidcIdTokenGeneratorService {

    public static final String CLAIM_PROFILE_ATTRIBUTES = "profile_attributes";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_EMAIL_VERIFIED = "email_verified";

    public static final List<TaraPrincipal.Attribute> validProfileAttributesToClaimsList = Collections.unmodifiableList(Arrays.asList(
        FAMILY_NAME, GIVEN_NAME, DATE_OF_BIRTH
    ));

    public TaraOidcIdTokenGeneratorService(final CasConfigurationProperties casProperties,
                                           final OidcIdTokenSigningAndEncryptionService signingService,
                                           final ServicesManager servicesManager) {
        super(casProperties, signingService, servicesManager);
    }

    @Override
    public String generate(final HttpServletRequest request,
                           final HttpServletResponse response,
                           final AccessToken accessTokenId,
                           final long timeoutInSeconds,
                           final OAuth20ResponseTypes responseType,
                           final OAuthRegisteredService registeredService) {

        if (!(registeredService instanceof OidcRegisteredService)) {
            throw new IllegalArgumentException("Registered service instance is not an OIDC service");
        }

        final OidcRegisteredService oidcRegisteredService = (OidcRegisteredService) registeredService;
        final J2EContext context = Pac4jUtils.getPac4jJ2EContext(request, response);
        final ProfileManager manager = Pac4jUtils.getPac4jProfileManager(request, response);
        final Optional<UserProfile> profile = manager.get(true);

        if (!profile.isPresent()) {
            throw new IllegalArgumentException("Unable to determine the user profile from the context");
        }

        log.debug("Attempting to produce claims for the id token [{}]", accessTokenId);
        final JwtClaims claims = produceIdTokenClaims(request, accessTokenId, timeoutInSeconds,
            oidcRegisteredService, profile.get(), context, responseType);
        log.debug("Produce claims for the id token [{}] as [{}]", accessTokenId, claims);


        // Needed for audit log (see "TARA_ACCESS_TOKEN_REQUEST_RESOURCE_RESOLVER")
        String encodedIdToken = getSigningService().encode(oidcRegisteredService, claims);
        request.setAttribute(Constants.TARA_OIDC_TOKEN_REQUEST_ATTR_ID_TOKEN, encodedIdToken);
        request.setAttribute(Constants.TARA_OIDC_TOKEN_REQUEST_ATTR_ACCESS_TOKEN_ID, accessTokenId.getId());
        return encodedIdToken;
    }

    @Override
    protected JwtClaims produceIdTokenClaims(final HttpServletRequest request,
                                             final AccessToken accessTokenId,
                                             final long timeoutInSeconds,
                                             final OidcRegisteredService service,
                                             final UserProfile profile,
                                             final J2EContext context,
                                             final OAuth20ResponseTypes responseType) {

        final Authentication authentication = accessTokenId.getAuthentication();
        final OidcProperties oidc = getCasProperties().getAuthn().getOidc();
        final JwtClaims claims = new JwtClaims();
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuer(oidc.getIssuer());
        claims.setAudience(service.getClientId());
        claims.setExpirationTime( getExpirationDate(timeoutInSeconds));
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(oidc.getSkew());

        setTaraClaims(accessTokenId, claims);

        claims.setClaim(OAuth20Constants.STATE, authentication.getAttributes().get(OAuth20Constants.STATE));
        claims.setClaim(OAuth20Constants.NONCE, authentication.getAttributes().get(OAuth20Constants.NONCE));
        claims.setClaim(OidcConstants.CLAIM_AT_HASH, generateAccessTokenHash(accessTokenId));
        return claims;
    }


    private void setTaraClaims(AccessToken accessToken, JwtClaims claims) {
        Assert.notNull(accessToken.getTicketGrantingTicket(), "No TGT associated with this access token!");
        Assert.notNull(accessToken.getTicketGrantingTicket().getAuthentication(), "No authentication associated with this TGT!");
        Principal taraPrincipal = TaraPrincipalFactory.createPrincipal(accessToken.getTicketGrantingTicket());

        claims.setSubject(getAttributeValue(SUB, taraPrincipal));

        if (taraPrincipal.getAttributes().containsKey(EMAIL.name()) && taraPrincipal.getAttributes().containsKey(EMAIL_VERIFIED.name())) {
            claims.setStringClaim(CLAIM_EMAIL, getAttributeValue(EMAIL, taraPrincipal));
            claims.setClaim(CLAIM_EMAIL_VERIFIED, getAttributeValue(EMAIL_VERIFIED, taraPrincipal, Boolean.class));
        }

        claims.setClaim(CLAIM_PROFILE_ATTRIBUTES, getProfileAttributesMap(taraPrincipal));
        claims.setStringListClaim(OidcConstants.AMR, getAttributeValue(AMR, taraPrincipal, List.class));

        if (taraPrincipal.getAttributes().containsKey(ACR.name())) {
            claims.setStringClaim(OidcConstants.ACR, getAttributeValue(ACR, taraPrincipal));
        }
    }

    private Map<String, Object> getProfileAttributesMap(Principal principal) {
        final Map<String, Object> principalAttributes = principal.getAttributes();
        final Map<String, Object> profileAttributes = new TreeMap(String.CASE_INSENSITIVE_ORDER);

        validProfileAttributesToClaimsList.forEach(key -> {
            Object value = principalAttributes.get(key.name().toLowerCase());
            if (value != null)
                profileAttributes.put(key.name().toLowerCase(), value);
        });

        return profileAttributes;
    }

    private String generateAccessTokenHash(final AccessToken accessTokenId) {
        final byte[] tokenBytes = accessTokenId.getId().getBytes();
        final String hashAlg;

        switch (getSigningService().getJsonWebKeySigningAlgorithm()) {
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                hashAlg = MessageDigestAlgorithms.SHA_512;
                break;
            case AlgorithmIdentifiers.RSA_USING_SHA256:
            default:
                hashAlg = MessageDigestAlgorithms.SHA_256;
        }

        log.debug("Digesting access token hash via algorithm [{}]", hashAlg);
        final byte[] digested = DigestUtils.rawDigest(hashAlg, tokenBytes);
        final byte[] hashBytesLeftHalf = Arrays.copyOf(digested, digested.length / 2);
        return EncodingUtils.encodeBase64(hashBytesLeftHalf);
    }

    private static String getAttributeValue(TaraPrincipal.Attribute attribute, Principal principal) {
        return getAttributeValue(attribute, principal, String.class);
    }

    private static <T> T getAttributeValue(TaraPrincipal.Attribute attribute, Principal principal, Class<T> clazz) {
        String attributeName = attribute.name();
        Assert.notNull(principal.getAttributes().get(attributeName), "Mandatory attribute " + attributeName + " not found when generating OIDC token");
        return (T)principal.getAttributes().get(attributeName);
    }

    private NumericDate getExpirationDate(long timeoutInSeconds) {
        final NumericDate expirationDate = NumericDate.now();
        expirationDate.addSeconds(timeoutInSeconds);
        return expirationDate;
    }
}

