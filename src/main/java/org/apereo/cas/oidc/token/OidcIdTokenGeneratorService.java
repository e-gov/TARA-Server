package org.apereo.cas.oidc.token;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.web.support.WebUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

public class OidcIdTokenGeneratorService {
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcIdTokenGeneratorService.class);

    @Autowired
    private CasConfigurationProperties casProperties;

    private final String issuer;
    private final int skew;
    private final OidcIdTokenSigningAndEncryptionService signingService;

    public OidcIdTokenGeneratorService(final String issuer,
                                       final int skew,
                                       final OidcIdTokenSigningAndEncryptionService signingService) {
        this.signingService = signingService;
        this.issuer = issuer;
        this.skew = skew;
    }

    /**
     * Generate string.
     *
     * @param request           the request
     * @param response          the response
     * @param accessTokenId     the access token id
     * @param timeout           the timeout
     * @param responseType      the response type
     * @param registeredService the registered service
     * @return the string
     * @throws Exception the exception
     */
    public String generate(final HttpServletRequest request,
                           final HttpServletResponse response,
                           final AccessToken accessTokenId,
                           final long timeout,
                           final OAuth20ResponseTypes responseType,
                           final OAuthRegisteredService registeredService) throws Exception {

        final OidcRegisteredService oidcRegisteredService = (OidcRegisteredService) registeredService;

        final J2EContext context = WebUtils.getPac4jJ2EContext(request, response);
        final ProfileManager manager = WebUtils.getPac4jProfileManager(request, response);
        final Optional<UserProfile> profile = manager.get(true);

        LOGGER.debug("Attempting to produce claims for the id token [{}]", accessTokenId);
        final JwtClaims claims = produceIdTokenClaims(request, accessTokenId, timeout,
            oidcRegisteredService, profile.get(), context, responseType);
        LOGGER.debug("Produce claims for the id token [{}] as [{}]", accessTokenId, claims);

        return this.signingService.encode(oidcRegisteredService, claims);
    }

    /**
     * Produce id token claims jwt claims.
     *
     * @param request       the request
     * @param accessTokenId the access token id
     * @param timeout       the timeout
     * @param service       the service
     * @param profile       the user profile
     * @param context       the context
     * @param responseType  the response type
     * @return the jwt claims
     */
    protected JwtClaims produceIdTokenClaims(final HttpServletRequest request,
                                             final AccessToken accessTokenId,
                                             final long timeout,
                                             final OidcRegisteredService service,
                                             final UserProfile profile,
                                             final J2EContext context,
                                             final OAuth20ResponseTypes responseType) {
        final Authentication authentication = accessTokenId.getAuthentication();
        final Principal principal = authentication.getPrincipal();

        final JwtClaims claims = new JwtClaims();
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuer(this.issuer);
        claims.setAudience(service.getClientId());

        final NumericDate expirationDate = NumericDate.now();
        expirationDate.addSeconds(timeout);
        claims.setExpirationTime(expirationDate);
        //claims.setExpirationTime(NumericDate.fromSeconds(15));
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(this.skew);
        claims.setSubject("EE" + principal.getId());
        claims.setClaim("profile_attributes", filterMobileIDAttributes(principal.getAttributes()));

        if (authentication.getAttributes().containsKey(casProperties.getAuthn().getMfa().getAuthenticationContextAttribute())) {
            final Collection<Object> val = CollectionUtils.toCollection(
                authentication.getAttributes().get(casProperties.getAuthn().getMfa().getAuthenticationContextAttribute()));
            claims.setStringClaim(OidcConstants.ACR, val.iterator().next().toString());
        }
        if (authentication.getAttributes().containsKey(AuthenticationHandler.SUCCESSFUL_AUTHENTICATION_HANDLERS)) {
            final Collection<Object> val = CollectionUtils.toCollection(
                authentication.getAttributes().get(AuthenticationHandler.SUCCESSFUL_AUTHENTICATION_HANDLERS));
            claims.setStringListClaim(OidcConstants.AMR, val.toArray(new String[]{}));
        }

        claims.setClaim(OAuth20Constants.STATE, authentication.getAttributes().get(OAuth20Constants.STATE));
        claims.setClaim(OAuth20Constants.NONCE, authentication.getAttributes().get(OAuth20Constants.NONCE));
        claims.setClaim(OidcConstants.CLAIM_AT_HASH, generateAccessTokenHash(accessTokenId, service));

		/*principal.getAttributes().entrySet().stream()
                .filter(entry -> casProperties.getAuthn().getOidc().getClaims().contains(entry.getKey()))
				.forEach(entry -> claims.setClaim(entry.getKey(), entry.getValue
				()));*/

        return claims;
    }

    // TODO
    private Map<String, Object> filterMobileIDAttributes(Map<String, Object> inputAttributes) {
        Map<String, Object> attrs = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        attrs.put("mobile_number", inputAttributes.get("mobileNumber"));
        attrs.put("family_name", inputAttributes.get("lastName"));
        attrs.put("given_name", inputAttributes.get("firstName"));
        return attrs;
    }

    private String generateAccessTokenHash(final AccessToken accessTokenId,
                                           final OidcRegisteredService service) {
        final byte[] tokenBytes = accessTokenId.getId().getBytes();
        final String hashAlg;

        switch (signingService.getJsonWebKeySigningAlgorithm()) {
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                hashAlg = MessageDigestAlgorithms.SHA_512;
                break;
            case AlgorithmIdentifiers.RSA_USING_SHA256:
            default:
                hashAlg = MessageDigestAlgorithms.SHA_256;
        }

        LOGGER.debug("Digesting access token hash via algorithm [{}]", hashAlg);
        final byte[] digested = DigestUtils.rawDigest(hashAlg, tokenBytes);
        final byte[] hashBytesLeftHalf = Arrays.copyOf(digested, digested.length / 2);
        return EncodingUtils.encodeBase64(hashBytesLeftHalf);
    }
}

