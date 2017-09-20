
package org.apereo.cas.support.oauth.web.endpoints;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.OAuth20Validator;
import org.apereo.cas.ticket.TicketState;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.hjson.JsonValue;
import org.hjson.Stringify;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;

/**
 *
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

public class OAuth20UserProfileControllerController extends BaseOAuth20Controller {
	private static final Logger LOGGER =
			LoggerFactory.getLogger(OAuth20UserProfileControllerController.class);
	private static final String ID = "id";
	private static final String ATTRIBUTES = "attributes";

	public OAuth20UserProfileControllerController(ServicesManager servicesManager,
			TicketRegistry ticketRegistry, OAuth20Validator validator,
			AccessTokenFactory accessTokenFactory, PrincipalFactory principalFactory,
			ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
			OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter,
			CasConfigurationProperties casProperties,
			CookieRetrievingCookieGenerator cookieGenerator) {
		super(servicesManager, ticketRegistry, validator, accessTokenFactory, principalFactory,
				webApplicationServiceServiceFactory, scopeToAttributesFilter, casProperties,
				cookieGenerator);
	}

	@GetMapping(
			path = { "/oauth2.0/profile" },
			produces = { "application/json" }
	)
	public ResponseEntity<String> handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		response.setContentType("application/json");
		String accessToken = this.getAccessTokenFromRequest(request);
		if (StringUtils.isBlank(accessToken)) {
			LOGGER.error("Missing [{}]", "access_token");
			return buildUnauthorizedResponseEntity("missing_accessToken");
		} else {
			AccessToken accessTokenTicket =
					(AccessToken) this.ticketRegistry.getTicket(accessToken, AccessToken.class);
			if (accessTokenTicket != null && !accessTokenTicket.isExpired()) {
				this.updateAccessTokenUsage(accessTokenTicket);
				Map map = this.writeOutProfileResponse(accessTokenTicket);
				String value = OAuth20Utils.jsonify(map);
				LOGGER.debug("Final user profile is [{}]",
						JsonValue.readHjson(value).toString(Stringify.FORMATTED));
				return new ResponseEntity(value, HttpStatus.OK);
			} else {
				LOGGER.error("Expired/Missing access token: [{}]", accessToken);
				return buildUnauthorizedResponseEntity("expired_accessToken");
			}
		}
	}

	private void updateAccessTokenUsage(AccessToken accessTokenTicket) {
		TicketState accessTokenState = (TicketState) TicketState.class.cast(accessTokenTicket);
		accessTokenState.update();
		if (accessTokenTicket.isExpired()) {
			this.ticketRegistry.deleteTicket(accessTokenTicket.getId());
		} else {
			this.ticketRegistry.updateTicket(accessTokenTicket);
		}

	}

	protected String getAccessTokenFromRequest(HttpServletRequest request) {
		String accessToken = request.getParameter("access_token");
		if (StringUtils.isBlank(accessToken)) {
			String authHeader = request.getHeader("Authorization");
			if (StringUtils.isNotBlank(authHeader) && authHeader.toLowerCase()
					.startsWith("Bearer".toLowerCase() + ' ')) {
				accessToken = authHeader.substring("Bearer".length() + 1);
			}
		}

		LOGGER.debug("[{}]: [{}]", "access_token", accessToken);
		return accessToken;
	}

	protected Map<String, Object> writeOutProfileResponse(AccessToken accessToken)
			throws IOException {
		Principal principal = accessToken.getAuthentication().getPrincipal();
		LOGGER.debug("Preparing user profile response based on CAS principal [{}]", principal);
		HashMap map = new HashMap();
		map.put("id", principal.getId());
		map.put("attributes", principal.getAttributes());
		return map;
	}

	private static ResponseEntity buildUnauthorizedResponseEntity(String code) {
		LinkedMultiValueMap map = new LinkedMultiValueMap(1);
		map.add("error", code);
		String value = OAuth20Utils.jsonify(map);
		return new ResponseEntity(value, HttpStatus.UNAUTHORIZED);
	}
}
