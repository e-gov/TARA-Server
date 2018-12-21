package ee.ria.sso.oidc;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.web.controllers.OidcAuthorizeEndpointController;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.validator.authorization.OAuth20AuthorizationRequestValidator;
import org.apereo.cas.support.oauth.web.response.callback.OAuth20AuthorizationResponseBuilder;
import org.apereo.cas.support.oauth.web.views.ConsentApprovalViewResolver;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

@Slf4j
public class TaraOidcAuthorizeEndpointController extends OidcAuthorizeEndpointController {
    public TaraOidcAuthorizeEndpointController(final ServicesManager servicesManager,
                                               final TicketRegistry ticketRegistry,
                                               final AccessTokenFactory accessTokenFactory,
                                               final PrincipalFactory principalFactory,
                                               final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
                                               final OAuthCodeFactory oAuthCodeFactory,
                                               final ConsentApprovalViewResolver consentApprovalViewResolver,
                                               final OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter,
                                               final CasConfigurationProperties casProperties,
                                               final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator,
                                               final OAuth20CasAuthenticationBuilder authenticationBuilder,
                                               final Set<OAuth20AuthorizationResponseBuilder> oauthAuthorizationResponseBuilders,
                                               final Set<OAuth20AuthorizationRequestValidator> oauthRequestValidators,
                                               final AuditableExecution registeredServiceAccessStrategyEnforcer) {
        super(servicesManager, ticketRegistry, accessTokenFactory, principalFactory,
            webApplicationServiceServiceFactory, oAuthCodeFactory, consentApprovalViewResolver,
            scopeToAttributesFilter, casProperties, ticketGrantingTicketCookieGenerator,
            authenticationBuilder, oauthAuthorizationResponseBuilders, oauthRequestValidators,
            registeredServiceAccessStrategyEnforcer);
    }

    @GetMapping(value = '/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.AUTHORIZE_URL)
    @Override
    public ModelAndView handleRequest(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        return super.handleRequest(request, response);
    }

    @PostMapping(value = '/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.AUTHORIZE_URL)
    @Override
    public ModelAndView handleRequestPost(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        return handleRequest(request, response);
    }
}
