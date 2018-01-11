//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.support.oauth.web.endpoints;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.OAuth20Validator;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestDataHolder;
import org.apereo.cas.support.oauth.web.views.ConsentApprovalViewResolver;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.apereo.cas.web.support.CookieUtils;
import org.apereo.cas.web.support.WebUtils;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

public class OAuth20AuthorizeEndpointController extends BaseOAuth20Controller {
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth20AuthorizeEndpointController.class);
	protected OAuthCodeFactory oAuthCodeFactory;
	protected final ConsentApprovalViewResolver consentApprovalViewResolver;
	protected final OAuth20CasAuthenticationBuilder authenticationBuilder;

	public OAuth20AuthorizeEndpointController(ServicesManager servicesManager, TicketRegistry ticketRegistry, OAuth20Validator validator, AccessTokenFactory accessTokenFactory, PrincipalFactory principalFactory, ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory, OAuthCodeFactory oAuthCodeFactory, ConsentApprovalViewResolver consentApprovalViewResolver, OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter, CasConfigurationProperties casProperties, CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator, OAuth20CasAuthenticationBuilder authenticationBuilder) {
		super(servicesManager, ticketRegistry, validator, accessTokenFactory, principalFactory, webApplicationServiceServiceFactory, scopeToAttributesFilter, casProperties, ticketGrantingTicketCookieGenerator);
		this.oAuthCodeFactory = oAuthCodeFactory;
		this.consentApprovalViewResolver = consentApprovalViewResolver;
		this.authenticationBuilder = authenticationBuilder;
	}

	@GetMapping(
			path = {"/oauth2.0/authorize"}
	)
	public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		J2EContext context = WebUtils.getPac4jJ2EContext(request, response);
		ProfileManager manager = WebUtils.getPac4jProfileManager(request, response);
		if(this.verifyAuthorizeRequest(request) && isRequestAuthenticated(manager, context)) {
			String clientId = context.getRequestParameter("client_id");
			OAuthRegisteredService registeredService = this.getRegisteredServiceByClientId(clientId);
			try {
				RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(clientId, registeredService);
			} catch (Exception var8) {
				LOGGER.error(var8.getMessage(), var8);
				return OAuth20Utils.produceUnauthorizedErrorView();
			}
			ModelAndView mv = this.consentApprovalViewResolver.resolve(context, registeredService);
			return !mv.isEmpty() && mv.hasView()?mv:this.redirectToCallbackRedirectUrl(manager, registeredService, context, clientId);
		} else {
			LOGGER.error("Authorize request verification failed");
			return OAuth20Utils.produceUnauthorizedErrorView();
		}
	}

	protected OAuthRegisteredService getRegisteredServiceByClientId(String clientId) {
		return OAuth20Utils.getRegisteredOAuthService(this.servicesManager, clientId);
	}

	private static boolean isRequestAuthenticated(ProfileManager manager, J2EContext context) {
		Optional opt = manager.get(true);
		return opt.isPresent();
	}

	protected ModelAndView redirectToCallbackRedirectUrl(ProfileManager manager, OAuthRegisteredService registeredService, J2EContext context, String clientId) throws Exception {
		Optional profile = manager.get(true);
		if(profile != null && profile.isPresent()) {
			Service service = this.authenticationBuilder.buildService(registeredService, context, false);
			LOGGER.debug("Created service [{}] based on registered service [{}]", service, registeredService);
			Authentication authentication = this.authenticationBuilder.build((UserProfile)profile.get(), registeredService, context, service);
			LOGGER.debug("Created OAuth authentication [{}] for service [{}]", service, authentication);

			try {
				RegisteredServiceAccessStrategyUtils.ensurePrincipalAccessIsAllowedForService(service, registeredService, authentication);
			} catch (PrincipalException | UnauthorizedServiceException var13) {
				LOGGER.error(var13.getMessage(), var13);
				return OAuth20Utils.produceUnauthorizedErrorView();
			}

			String redirectUri = context.getRequestParameter("redirect_uri");
			LOGGER.debug("Authorize request verification successful for client [{}] with redirect uri [{}]", clientId, redirectUri);
			String responseType = context.getRequestParameter("response_type");
			TicketGrantingTicket ticketGrantingTicket = CookieUtils.getTicketGrantingTicketFromRequest(this.ticketGrantingTicketCookieGenerator, this.ticketRegistry, context.getRequest());
			String callbackUrl;
			if(OAuth20Utils.isResponseType(responseType, OAuth20ResponseTypes.CODE)) {
				callbackUrl = this.buildCallbackUrlForAuthorizationCodeResponseType(authentication, service, redirectUri, ticketGrantingTicket);
			} else if(OAuth20Utils.isResponseType(responseType, OAuth20ResponseTypes.TOKEN)) {
				AccessTokenRequestDataHolder holder = new AccessTokenRequestDataHolder(service, authentication, registeredService, ticketGrantingTicket);
				callbackUrl = this.buildCallbackUrlForImplicitTokenResponseType(holder, redirectUri);
			} else {
				callbackUrl = this.buildCallbackUrlForTokenResponseType(context, authentication, service, redirectUri, responseType, clientId);
			}

			LOGGER.debug("Callback URL to redirect: [{}]", callbackUrl);
			context.getRequest().getSession().invalidate();
			removeCookie(context);
			return StringUtils.isBlank(callbackUrl)?OAuth20Utils.produceUnauthorizedErrorView():OAuth20Utils.redirectTo(callbackUrl);
		} else {
			LOGGER.error("Unexpected null profile from profile manager. Request is not fully authenticated.");
			return OAuth20Utils.produceUnauthorizedErrorView();
		}
	}

	private void removeCookie(J2EContext context) {
		Cookie cookie = new Cookie(ticketGrantingTicketCookieGenerator.getCookieName(), null); // Not necessary, but saves bandwidth.
		cookie.setPath(ticketGrantingTicketCookieGenerator.getCookiePath());
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setMaxAge(0);
		context.getResponse().addCookie(cookie);
	}

	protected String buildCallbackUrlForTokenResponseType(J2EContext context, Authentication authentication, Service service, String redirectUri, String responseType, String clientId) {
		return null;
	}

	private String buildCallbackUrlForImplicitTokenResponseType(AccessTokenRequestDataHolder holder, String redirectUri) throws Exception {
		AccessToken accessToken = this.generateAccessToken(holder);
		LOGGER.debug("Generated OAuth access token: [{}]", accessToken);
		return this.buildCallbackUrlResponseType(holder.getAuthentication(), holder.getService(), redirectUri, accessToken, Collections.emptyList());
	}

	protected String buildCallbackUrlResponseType(Authentication authentication, Service service, String redirectUri, AccessToken accessToken, List<NameValuePair> params) throws Exception {
		String state = authentication.getAttributes().get("state").toString();
		String nonce = authentication.getAttributes().get("nonce").toString();
		URIBuilder builder = new URIBuilder(redirectUri);
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("access_token").append('=').append(accessToken.getId()).append('&').append("token_type").append('=').append("bearer").append('&').append("expires_in").append('=').append(this.casProperties.getTicket().getTgt().getTimeToKillInSeconds());
		params.forEach((p) -> {
			stringBuilder.append('&').append(p.getName()).append('=').append(p.getValue());
		});
		if(StringUtils.isNotBlank(state)) {
			stringBuilder.append('&').append("state").append('=').append(EncodingUtils.urlEncode(state));
		}

		if(StringUtils.isNotBlank(nonce)) {
			stringBuilder.append('&').append("nonce").append('=').append(EncodingUtils.urlEncode(nonce));
		}

		builder.setFragment(stringBuilder.toString());
		String url = builder.toString();
		return url;
	}

	private String buildCallbackUrlForAuthorizationCodeResponseType(Authentication authentication, Service service, String redirectUri, TicketGrantingTicket ticketGrantingTicket) {
		OAuthCode code = this.oAuthCodeFactory.create(service, authentication, ticketGrantingTicket);
		LOGGER.debug("Generated OAuth code: [{}]", code);
		this.ticketRegistry.addTicket(code);
		String state = authentication.getAttributes().get("state").toString();
		String nonce = authentication.getAttributes().get("nonce").toString();
		String callbackUrl = CommonHelper.addParameter(redirectUri, "code", code.getId());
		if(StringUtils.isNotBlank(state)) {
			callbackUrl = CommonHelper.addParameter(callbackUrl, "state", state);
		}

		if(StringUtils.isNotBlank(nonce)) {
			callbackUrl = CommonHelper.addParameter(callbackUrl, "nonce", nonce);
		}

		return callbackUrl;
	}

	private boolean verifyAuthorizeRequest(HttpServletRequest request) {
		boolean checkParameterExist = this.validator.checkParameterExist(request, "client_id") && this.validator.checkParameterExist(request, "redirect_uri") && this.validator.checkParameterExist(request, "response_type");
		String responseType = request.getParameter("response_type");
		String clientId = request.getParameter("client_id");
		String redirectUri = request.getParameter("redirect_uri");
		OAuthRegisteredService registeredService = this.getRegisteredServiceByClientId(clientId);
		return checkParameterExist && checkResponseTypes(responseType, OAuth20ResponseTypes.values()) && this.validator.checkServiceValid(registeredService) && this.validator.checkCallbackValid(registeredService, redirectUri);
	}

	private static boolean checkResponseTypes(String type, OAuth20ResponseTypes... expectedTypes) {
		LOGGER.debug("Response type: [{}]", type);
		boolean checked = Stream.of(expectedTypes).anyMatch((t) -> {
			return OAuth20Utils.isResponseType(type, t);
		});
		if(!checked) {
			LOGGER.error("Unsupported response type: [{}]", type);
		}

		return checked;
	}
}
