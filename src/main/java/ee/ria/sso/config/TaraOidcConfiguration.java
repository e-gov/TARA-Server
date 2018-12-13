package ee.ria.sso.config;

import ee.ria.sso.oidc.*;
import org.apache.http.HttpStatus;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.oauth.OAuthProperties;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.oidc.discovery.OidcServerDiscoverySettings;
import org.apereo.cas.oidc.discovery.OidcServerDiscoverySettingsFactory;
import org.apereo.cas.oidc.token.OidcIdTokenGeneratorService;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.oidc.web.OidcAccessTokenResponseGenerator;
import org.apereo.cas.oidc.web.controllers.OidcAccessTokenEndpointController;
import org.apereo.cas.oidc.web.controllers.OidcAuthorizeEndpointController;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.authorization.OAuth20AuthorizationRequestValidator;
import org.apereo.cas.support.oauth.validator.token.OAuth20TokenRequestValidator;
import org.apereo.cas.support.oauth.web.response.accesstoken.AccessTokenResponseGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.OAuth20TokenGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.BaseAccessTokenGrantRequestExtractor;
import org.apereo.cas.support.oauth.web.response.callback.OAuth20AuthorizationResponseBuilder;
import org.apereo.cas.support.oauth.web.views.ConsentApprovalViewResolver;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.code.OAuthCodeExpirationPolicy;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.springframework.web.SecurityInterceptor;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
public class TaraOidcConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("oauthSecConfig")
    private ObjectProvider<Config> oauthSecConfig;

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    @Autowired
    @Qualifier("ticketRegistry")
    private TicketRegistry ticketRegistry;

    @Autowired
    @Qualifier("defaultAccessTokenFactory")
    private AccessTokenFactory defaultAccessTokenFactory;

    @Autowired
    @Qualifier("profileScopeToAttributesFilter")
    private OAuth20ProfileScopeToAttributesFilter profileScopeToAttributesFilter;

    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ServiceFactory<WebApplicationService> webApplicationServiceFactory;

    @Autowired
    @Qualifier("accessTokenExpirationPolicy")
    private ExpirationPolicy accessTokenExpirationPolicy;

    @Autowired
    @Qualifier("oauthTokenGenerator")
    private OAuth20TokenGenerator oauthTokenGenerator;

    @Autowired
    @Qualifier("accessTokenGrantRequestExtractors")
    private Collection<BaseAccessTokenGrantRequestExtractor> accessTokenGrantRequestExtractors;

    @Autowired
    @Qualifier("oauthTokenRequestValidators")
    private Collection<OAuth20TokenRequestValidator> oauthTokenRequestValidators;

    @Autowired
    @Qualifier("ticketGrantingTicketCookieGenerator")
    private ObjectProvider<CookieRetrievingCookieGenerator> ticketGrantingTicketCookieGenerator;

    @Autowired
    @Qualifier("oidcTokenSigningAndEncryptionService")
    private OidcIdTokenSigningAndEncryptionService oidcTokenSigningAndEncryptionService;

    @Autowired
    @Qualifier("taraPrincipalFactory")
    private PrincipalFactory taraPrincipalFactory;

    @Autowired
    @Qualifier("defaultOAuthCodeFactory")
    private OAuthCodeFactory defaultOAuthCodeFactory;

    @Autowired
    @Qualifier("oauthCasAuthenticationBuilder")
    private OAuth20CasAuthenticationBuilder authenticationBuilder;

    @Autowired
    @Qualifier("oauthAuthorizationResponseBuilders")
    private Set<OAuth20AuthorizationResponseBuilder> oauthAuthorizationResponseBuilders;

    @Autowired
    @Qualifier("oauthAuthorizationRequestValidators")
    private Set<OAuth20AuthorizationRequestValidator> oauthRequestValidators;

    @Autowired
    @Qualifier("registeredServiceAccessStrategyEnforcer")
    private AuditableExecution registeredServiceAccessStrategyEnforcer;

    @Autowired
    @Qualifier("consentApprovalViewResolver")
    private ConsentApprovalViewResolver consentApprovalViewResolver;

    @Bean
    public OidcAuthorizeEndpointController oidcAuthorizeController() {
        return new TaraOidcAuthorizeEndpointController(
                servicesManager,
                ticketRegistry,
                defaultAccessTokenFactory,
                oidcPrincipalFactory(),
                webApplicationServiceFactory,
                defaultOAuthCodeFactory,
                consentApprovalViewResolver,
                profileScopeToAttributesFilter,
                casProperties,
                ticketGrantingTicketCookieGenerator.getIfAvailable(),
                authenticationBuilder,
                oauthAuthorizationResponseBuilders,
                oauthRequestValidators,
                registeredServiceAccessStrategyEnforcer);
    }

    @Bean
    public OidcAccessTokenEndpointController oidcAccessTokenController() {
        return new TaraOidcAccessTokenEndpointController(
                servicesManager, ticketRegistry, defaultAccessTokenFactory,
                oidcPrincipalFactory(), webApplicationServiceFactory, oauthTokenGenerator,
                oidcAccessTokenResponseGenerator(), profileScopeToAttributesFilter, casProperties,
                ticketGrantingTicketCookieGenerator.getIfAvailable(), accessTokenExpirationPolicy,
                accessTokenGrantRequestExtractors, oauthTokenRequestValidators);
    }

    @Bean
    public AccessTokenResponseGenerator oidcAccessTokenResponseGenerator() {
        return new OidcAccessTokenResponseGenerator(oidcIdTokenGenerator());
    }

    @Bean
    @RefreshScope
    public OidcIdTokenGeneratorService oidcIdTokenGenerator() {
        return new TaraOidcIdTokenGeneratorService(
                casProperties,
                oidcTokenSigningAndEncryptionService,
                servicesManager);
    }

    @Bean
    public PrincipalFactory oidcPrincipalFactory() {
        return taraPrincipalFactory;
    }

    @Bean
    public FactoryBean<OidcServerDiscoverySettings> oidcServerDiscoverySettingsFactory() {
        return new OidcServerDiscoverySettingsFactory(casProperties) {
            @Override
            public OidcServerDiscoverySettings getObject() {
                final OidcProperties oidc = casProperties.getAuthn().getOidc();
                final OidcServerDiscoverySettings discoveryProperties =
                        new OidcServerDiscoverySettings(casProperties, oidc.getIssuer());
                discoveryProperties.setClaimsSupported(oidc.getClaims());
                discoveryProperties.setScopesSupported(oidc.getScopes());
                discoveryProperties.setResponseTypesSupported(
                        Collections.singletonList(OAuth20ResponseTypes.CODE.getType()));
                discoveryProperties.setSubjectTypesSupported(oidc.getSubjectTypes());
                discoveryProperties.setClaimTypesSupported(Collections.singletonList("normal"));
                discoveryProperties.setGrantTypesSupported(
                        Collections.singletonList(OAuth20GrantTypes.AUTHORIZATION_CODE.getType()));
                discoveryProperties.setIdTokenSigningAlgValuesSupported(Arrays.asList("none", "RS256"));
                return discoveryProperties;
            }
        };
    }

    @Bean
    public SecurityInterceptor requiresAuthenticationAccessTokenInterceptor() {
        final String clients = Stream.of(Authenticators.CAS_OAUTH_CLIENT_BASIC_AUTHN,
                Authenticators.CAS_OAUTH_CLIENT_DIRECT_FORM,
                Authenticators.CAS_OAUTH_CLIENT_USER_FORM).collect(Collectors.joining(","));
        SecurityInterceptor securityInterceptor = new SecurityInterceptor(oauthSecConfig.getIfAvailable(), clients);
        securityInterceptor.setSecurityLogic(new DefaultSecurityLogic<Boolean, J2EContext>() {
            @Override
            protected HttpAction unauthorized(J2EContext context, List<Client> currentClients) {
                OAuth20Utils.writeText(context.getResponse(), "{\"" + OAuth20Constants.ERROR + "\":\"" + OAuth20Constants.INVALID_CLIENT + "\"}" , HttpStatus.SC_UNAUTHORIZED);
                return super.unauthorized(context, currentClients);
            }
        });
        return securityInterceptor;
    }

    @Bean
    public FilterRegistrationBean oidcAuthorizeCheckingServletFilter() {
        final Map<String, String> initParams = new HashMap<>();
        final FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(new OidcAuthorizeRequestValidationServletFilter());
        bean.setUrlPatterns(Collections.singleton("/oidc/authorize"));
        bean.setInitParameters(initParams);
        bean.setName("oidcAuthorizeCheckingServletFilter");
        bean.setOrder(Ordered.LOWEST_PRECEDENCE);
        return bean;
    }

    @Configuration("TaraOauthConfiguration")
    public class TaraOauthConfiguration {

        @Autowired
        @Qualifier("oAuthCodeIdGenerator")
        private UniqueTicketIdGenerator oAuthCodeIdGenerator;

        @Bean
        public OAuthCodeFactory defaultOAuthCodeFactory() {
            return new TaraDefaultOAuthCodeFactory(oAuthCodeIdGenerator, oAuthCodeExpirationPolicy());
        }

        private ExpirationPolicy oAuthCodeExpirationPolicy() {
            final OAuthProperties oauth = casProperties.getAuthn().getOauth();
            return new OAuthCodeExpirationPolicy(oauth.getCode().getNumberOfUses(),
                    oauth.getCode().getTimeToKillInSeconds());
        }
    }
}
