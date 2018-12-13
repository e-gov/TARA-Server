package ee.ria.sso.oidc;

import com.google.common.base.Preconditions;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.utils.EstonianIdCodeUtil;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
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
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.Pac4jUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * This is {@link TaraOidcIdTokenGeneratorService}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Slf4j
@Getter
public class TaraOidcIdTokenGeneratorService extends OidcIdTokenGeneratorService {

    private static final List<String> validProfileAttributes = Arrays.asList(
            "family_name", "given_name", "date_of_birth"
    );

    public TaraOidcIdTokenGeneratorService(final CasConfigurationProperties casProperties,
                                           final OidcIdTokenSigningAndEncryptionService signingService,
                                           final ServicesManager servicesManager) {
        super(casProperties, signingService, servicesManager);
    }

    /**
     * Generate string.
     *
     * @param request           the request
     * @param response          the response
     * @param accessTokenId     the access token id
     * @param timeoutInSeconds  the timeoutInSeconds
     * @param responseType      the response type
     * @param registeredService the registered service
     * @return the string
     */
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

        // Needed for audit log (see "TARA_ID_TOKEN_REQUEST_RESOURCE_RESOLVER")
        String encodedIdToken = getSigningService().encode(oidcRegisteredService, claims);
        request.setAttribute("generatedAndEncodedIdTokenString", encodedIdToken);

        return getSigningService().encode(oidcRegisteredService, claims);
    }

    /**
     * Produce id token claims jwt claims.
     *
     * @param request          the request
     * @param accessTokenId    the access token id
     * @param timeoutInSeconds the timeoutInSeconds
     * @param service          the service
     * @param profile          the user profile
     * @param context          the context
     * @param responseType     the response type
     * @return the jwt claims
     */
    protected JwtClaims produceIdTokenClaims(final HttpServletRequest request,
                                             final AccessToken accessTokenId,
                                             final long timeoutInSeconds,
                                             final OidcRegisteredService service,
                                             final UserProfile profile,
                                             final J2EContext context,
                                             final OAuth20ResponseTypes responseType) {

        final Authentication authentication = accessTokenId.getAuthentication();
        final OidcProperties oidc = getCasProperties().getAuthn().getOidc();
        final Principal principal = authentication.getPrincipal();

        final JwtClaims claims = new JwtClaims();
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuer(oidc.getIssuer());
        claims.setAudience(service.getClientId());

        final NumericDate expirationDate = NumericDate.now();
        expirationDate.addSeconds(timeoutInSeconds);
        claims.setExpirationTime(expirationDate);
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(oidc.getSkew());
        claims.setSubject(principal.getId());

        Principal _principal = accessTokenId.getTicketGrantingTicket().getAuthentication().getPrincipal();
        claims.setClaim("profile_attributes", getProfileAttributesMap(_principal));
        claims.setStringListClaim(OidcConstants.AMR, getAmrValuesList(_principal));

        if (isOfAuthenticationType(_principal, AuthenticationType.eIDAS)) {
            String levelOfAssurance = (String) ((List)_principal.getAttributes().get("level_of_assurance")).get(0);
            if (levelOfAssurance != null) claims.setStringClaim(OidcConstants.ACR, levelOfAssurance);
        }

        claims.setClaim(OAuth20Constants.STATE, authentication.getAttributes().get(OAuth20Constants.STATE));
        claims.setClaim(OAuth20Constants.NONCE, authentication.getAttributes().get(OAuth20Constants.NONCE));
        claims.setClaim(OidcConstants.CLAIM_AT_HASH, generateAccessTokenHash(accessTokenId));

        return claims;
    }

    private Entry<String, Service> getOAuthServiceTicket(final TicketGrantingTicket tgt) {
        final Optional<Entry<String, Service>> oAuthServiceTicket = Stream.concat(
            tgt.getServices().entrySet().stream(),
            tgt.getProxyGrantingTickets().entrySet().stream())
            .filter(e -> getServicesManager().findServiceBy(e.getValue()).getServiceId().equals(getOAuthCallbackUrl()))
            .findFirst();
        Preconditions.checkState(oAuthServiceTicket.isPresent(), "Cannot find service ticket issued to " + getOAuthCallbackUrl() + " as part of the authentication context");
        return oAuthServiceTicket.get();
    }

    private String generateAccessTokenHash(final AccessToken accessTokenId,
                                           final OidcRegisteredService service) {
        final byte[] tokenBytes = accessTokenId.getId().getBytes(StandardCharsets.UTF_8);
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
        return EncodingUtils.encodeUrlSafeBase64(hashBytesLeftHalf);
    }

    private static Object getAuthenticationType(Principal principal) {
        return ((List)(principal.getAttributes().get("authentication_type"))).get(0);
    }

    private static boolean isOfAuthenticationType(Principal principal, AuthenticationType type) {
        return type.getAmrName().equals(getAuthenticationType(principal));
    }

    private Map<String, Object> getProfileAttributesMap(Principal principal) {
        final Map<String, Object> principalAttributes = principal.getAttributes();
        final Map<String, Object> profileAttributes = new TreeMap(String.CASE_INSENSITIVE_ORDER);

        validProfileAttributes.forEach(key -> {
            Object value = principalAttributes.get(key);
            if (value != null)
                profileAttributes.put(key, ((List)value).get(0));
        });

        if (profileAttributes.get("date_of_birth") == null) {
            Object principalCode = principalAttributes.get("principal_code");
            if (principalCode != null && EstonianIdCodeUtil.isEEPrefixedEstonianIdCode(((List)principalCode).get(0).toString())) {
                profileAttributes.put("date_of_birth", EstonianIdCodeUtil.extractDateOfBirthFromEEPrefixedEstonianIdCode(((List)principalCode).get(0).toString()));
            }
        }

        return profileAttributes;
    }

    private List<String> getAmrValuesList(Principal principal) {
        return CollectionUtils.toCollection(getAuthenticationType(principal)).stream()
                .map(e -> e.toString()).collect(Collectors.toList());
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
}

