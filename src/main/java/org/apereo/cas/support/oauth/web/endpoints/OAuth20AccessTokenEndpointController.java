package org.apereo.cas.support.oauth.web.endpoints;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.profile.OAuthClientProfile;
import org.apereo.cas.support.oauth.profile.OAuthUserProfile;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.OAuth20Validator;
import org.apereo.cas.support.oauth.web.response.accesstoken.AccessTokenResponseGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenAuthorizationCodeGrantRequestExtractor;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenPasswordGrantRequestExtractor;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRefreshTokenGrantRequestExtractor;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestDataHolder;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.BaseAccessTokenGrantRequestExtractor;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.refreshtoken.RefreshToken;
import org.apereo.cas.ticket.refreshtoken.RefreshTokenFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.apereo.cas.web.support.WebUtils;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;

import com.google.common.base.Throwables;

import ee.ria.sso.flow.JSONFlowExecutionException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class OAuth20AccessTokenEndpointController extends BaseOAuth20Controller {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth20AccessTokenEndpointController.class);
    @Autowired
    private CasConfigurationProperties casProperties;
    private final RefreshTokenFactory refreshTokenFactory;
    private final AccessTokenResponseGenerator accessTokenResponseGenerator;
    private final OAuth20CasAuthenticationBuilder authenticationBuilder;
    private final CentralAuthenticationService centralAuthenticationService;

    public OAuth20AccessTokenEndpointController(ServicesManager servicesManager, TicketRegistry ticketRegistry,
                                                OAuth20Validator validator, AccessTokenFactory accessTokenFactory,
                                                PrincipalFactory principalFactory,
                                                ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
                                                RefreshTokenFactory refreshTokenFactory,
                                                AccessTokenResponseGenerator accessTokenResponseGenerator,
                                                OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter,
                                                CasConfigurationProperties casProperties,
                                                CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator,
                                                OAuth20CasAuthenticationBuilder authenticationBuilder,
                                                CentralAuthenticationService centralAuthenticationService) {
        super(servicesManager, ticketRegistry, validator, accessTokenFactory, principalFactory, webApplicationServiceServiceFactory,
            scopeToAttributesFilter, casProperties, ticketGrantingTicketCookieGenerator);
        this.refreshTokenFactory = refreshTokenFactory;
        this.accessTokenResponseGenerator = accessTokenResponseGenerator;
        this.authenticationBuilder = authenticationBuilder;
        this.centralAuthenticationService = centralAuthenticationService;
    }

    @PostMapping(
        path = {"/oauth2.0/accessToken"}
    )
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            response.setContentType("text/plain");
            if (!this.verifyAccessTokenRequest(request, response)) {
                throw JSONFlowExecutionException.ofBadRequest(Collections.singletonMap("error", "invalid_request"),
                    new RuntimeException("Access token request verification failed"));
            } else {
                AccessTokenRequestDataHolder responseHolder;
                try {
                    responseHolder = this.examineAndExtractAccessTokenGrantRequest(request, response);
                    LOGGER.debug("Creating access token for [{}]", responseHolder);
                } catch (Exception e) {
                    throw JSONFlowExecutionException.ofBadRequest(Collections.singletonMap("error", "invalid_grant"),
                        new RuntimeException("Could not identify and extract access token request", e));
                }
                J2EContext context = WebUtils.getPac4jJ2EContext(request, response);
                AccessToken accessToken = this.generateAccessToken(responseHolder);
                LOGGER.debug("Access token generated is: [{}]", accessToken);
                RefreshToken refreshToken = null;
                if (responseHolder.isGenerateRefreshToken()) {
                    refreshToken = this.generateRefreshToken(responseHolder);
                    LOGGER.debug("Refresh Token: [{}]", refreshToken);
                } else {
                    LOGGER.debug("Service [{}] is not able/allowed to receive refresh tokens", responseHolder.getService());
                }
                this.generateAccessTokenResponse(request, response, responseHolder, context, accessToken, refreshToken);
                response.setStatus(200);
            }
        } catch (Exception var8) {
            LOGGER.error(var8.getMessage(), var8);
            throw Throwables.propagate(var8);
        }
    }

    private RefreshToken generateRefreshToken(AccessTokenRequestDataHolder responseHolder) {
        LOGGER.debug("Creating refresh token for [{}]", responseHolder.getService());
        RefreshToken refreshToken = this.refreshTokenFactory.create(responseHolder.getService(), responseHolder.getAuthentication(),
            responseHolder.getTicketGrantingTicket());
        LOGGER.debug("Adding refresh token [{}] to the registry", refreshToken);
        this.addTicketToRegistry(refreshToken, responseHolder.getTicketGrantingTicket());
        return refreshToken;
    }

    private void generateAccessTokenResponse(HttpServletRequest request, HttpServletResponse response,
                                             AccessTokenRequestDataHolder responseHolder, J2EContext context,
                                             AccessToken accessToken, RefreshToken refreshToken) {
        LOGGER.debug("Generating access token response for [{}]", accessToken);
        OAuth20ResponseTypes type = getOAuth20ResponseType(context);
        LOGGER.debug("Located response type as [{}]", type);
        this.accessTokenResponseGenerator.generate(request, response, responseHolder.getRegisteredService(),
            responseHolder.getService(), accessToken, refreshToken,
            this.casProperties.getAuthn().getOauth().getAccessToken().getMaxTimeToLiveInSeconds(), type);
    }

    private static OAuth20ResponseTypes getOAuth20ResponseType(J2EContext context) {
        String responseType = context.getRequestParameter("response_type");
        OAuth20ResponseTypes type = Arrays.stream(OAuth20ResponseTypes.values()).filter((t) ->
            t.getType().equalsIgnoreCase(responseType)
        ).findFirst().orElse(OAuth20ResponseTypes.CODE);
        LOGGER.debug("OAuth response type is [{}]", type);
        return type;
    }

    private AccessTokenRequestDataHolder examineAndExtractAccessTokenGrantRequest(HttpServletRequest request, HttpServletResponse response) {
        List<BaseAccessTokenGrantRequestExtractor> list = Arrays.asList(
            new AccessTokenAuthorizationCodeGrantRequestExtractor(this.servicesManager, this.ticketRegistry, request,
                response, this.centralAuthenticationService, this.casProperties.getAuthn().getOauth()),
            new AccessTokenRefreshTokenGrantRequestExtractor(this.servicesManager, this.ticketRegistry, request, response,
                this.centralAuthenticationService, this.casProperties.getAuthn().getOauth()),
            new AccessTokenPasswordGrantRequestExtractor(this.servicesManager, this.ticketRegistry, request, response,
                this.authenticationBuilder, this.centralAuthenticationService, this.casProperties.getAuthn().getOauth()));
        return (list.stream().filter((ext) -> ext.supports(request)).findFirst().orElseThrow(() ->
            new UnsupportedOperationException("Request is not supported"))).extract();
    }

    private boolean verifyAccessTokenRequest(HttpServletRequest request, HttpServletResponse response) {
        String grantType = request.getParameter("grant_type");
        if (!isGrantTypeSupported(grantType, OAuth20GrantTypes.AUTHORIZATION_CODE, OAuth20GrantTypes.PASSWORD,
            OAuth20GrantTypes.REFRESH_TOKEN)) {
            LOGGER.warn("Grant type is not supported: [{}]", grantType);
            return false;
        } else {
            ProfileManager manager = WebUtils.getPac4jProfileManager(request, response);
            Optional<UserProfile> profile = manager.get(true);
            if (profile != null && profile.isPresent()) {
                UserProfile uProfile = profile.get();
                String clientId;
                if (OAuth20Utils.isGrantType(grantType, OAuth20GrantTypes.AUTHORIZATION_CODE)) {
                    clientId = uProfile.getId();
                    String redirectUri = request.getParameter("redirect_uri");
                    OAuthRegisteredService registeredService = OAuth20Utils.getRegisteredOAuthService(this.servicesManager, clientId);
                    LOGGER.debug("Received grant type [{}] with client id [{}] and redirect URI [{}]", new Object[]{
                        grantType, clientId, redirectUri});
                    return uProfile instanceof OAuthClientProfile && this.validator.checkParameterExist(request, "redirect_uri") &&
                        this.validator.checkParameterExist(request, "code") && this.validator.checkCallbackValid(registeredService, redirectUri);
                } else if (OAuth20Utils.isGrantType(grantType, OAuth20GrantTypes.REFRESH_TOKEN)) {
                    return uProfile instanceof OAuthClientProfile && this.validator.checkParameterExist(request, "refresh_token");
                } else if (!OAuth20Utils.isGrantType(grantType, OAuth20GrantTypes.PASSWORD)) {
                    return false;
                } else {
                    clientId = request.getParameter("client_id");
                    LOGGER.debug("Received grant type [{}] with client id [{}]", grantType, clientId);
                    OAuthRegisteredService registeredService = OAuth20Utils.getRegisteredOAuthService(this.servicesManager, clientId);
                    return uProfile instanceof OAuthUserProfile && this.validator.checkParameterExist(request, "client_id") &&
                        this.validator.checkServiceValid(registeredService);
                }
            } else {
                LOGGER.warn("Could not locate authenticated profile for this request");
                return false;
            }
        }
    }

    private static boolean isGrantTypeSupported(String type, OAuth20GrantTypes... expectedTypes) {
        LOGGER.debug("Grant type: [{}]", type);
        OAuth20GrantTypes[] var2 = expectedTypes;
        int var3 = expectedTypes.length;
        for (int var4 = 0; var4 < var3; ++var4) {
            OAuth20GrantTypes expectedType = var2[var4];
            if (OAuth20Utils.isGrantType(type, expectedType)) {
                return true;
            }
        }
        LOGGER.error("Unsupported grant type: [{}]", type);
        return false;
    }

}
