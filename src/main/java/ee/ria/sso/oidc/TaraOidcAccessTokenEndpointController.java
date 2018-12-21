package ee.ria.sso.oidc;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.web.controllers.OidcAccessTokenEndpointController;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.token.OAuth20TokenRequestValidator;
import org.apereo.cas.support.oauth.web.response.accesstoken.AccessTokenResponseGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.OAuth20TokenGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.BaseAccessTokenGrantRequestExtractor;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

@Slf4j
public class TaraOidcAccessTokenEndpointController extends OidcAccessTokenEndpointController {

    public TaraOidcAccessTokenEndpointController(final ServicesManager servicesManager,
                                                 final TicketRegistry ticketRegistry,
                                                 final AccessTokenFactory accessTokenFactory,
                                                 final PrincipalFactory principalFactory,
                                                 final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
                                                 final OAuth20TokenGenerator accessTokenGenerator,
                                                 final AccessTokenResponseGenerator accessTokenResponseGenerator,
                                                 final OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter,
                                                 final CasConfigurationProperties casProperties,
                                                 final CookieRetrievingCookieGenerator cookieGenerator,
                                                 final ExpirationPolicy accessTokenExpirationPolicy,
                                                 final Collection<BaseAccessTokenGrantRequestExtractor> accessTokenGrantRequestExtractors,
                                                 final Collection<OAuth20TokenRequestValidator> accessTokenGrantRequestValidators) {
        super(servicesManager,
                ticketRegistry,
                accessTokenFactory,
                principalFactory,
                webApplicationServiceServiceFactory,
                accessTokenGenerator,
                accessTokenResponseGenerator,
                scopeToAttributesFilter,
                casProperties,
                cookieGenerator,
                accessTokenExpirationPolicy,
                accessTokenGrantRequestExtractors,
                accessTokenGrantRequestValidators);
    }

    @Audit(
            action = "ACCESS_TOKEN_REQUEST_HANDLING",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_ACCESS_TOKEN_REQUEST_RESOURCE_RESOLVER"
    )
    @PostMapping(value = {'/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.ACCESS_TOKEN_URL,
            '/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.TOKEN_URL})
    @Override
    public void handleRequest(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        process(request, response);
    }

    @Audit(
            action = "ACCESS_TOKEN_REQUEST_HANDLING",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_ACCESS_TOKEN_REQUEST_RESOURCE_RESOLVER"
    )
    @GetMapping(value = {'/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.ACCESS_TOKEN_URL,
            '/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.TOKEN_URL})
    @Override
    public void handleGetRequest(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        process(request, response);
    }


    private void process(HttpServletRequest request, HttpServletResponse response) throws Exception {

        final String grantType = request.getParameter(OAuth20Constants.GRANT_TYPE);
        if (StringUtils.isNotEmpty(grantType) && !OAuth20GrantTypes.AUTHORIZATION_CODE.getType().equals(grantType)) {
            log.error("Grant type is not supported: [{}]", grantType);
            OAuth20Utils.writeTextError(response, "unsupported_grant_type");
            return;
        }

        super.handleRequest(request, response);
    }
}