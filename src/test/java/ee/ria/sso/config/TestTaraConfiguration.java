package ee.ria.sso.config;

import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.audit.AuditTrailExecutionPlan;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlan;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.audit.spi.DefaultAuditTrailRecordResolutionPlan;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.oidc.util.OidcAuthorizationRequestSupport;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.validator.authorization.OAuth20AuthorizationRequestValidator;
import org.apereo.cas.support.oauth.validator.token.OAuth20TokenRequestValidator;
import org.apereo.cas.support.oauth.web.response.accesstoken.OAuth20TokenGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.BaseAccessTokenGrantRequestExtractor;
import org.apereo.cas.support.oauth.web.response.callback.OAuth20AuthorizationResponseBuilder;
import org.apereo.cas.support.oauth.web.views.ConsentApprovalViewResolver;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.mockito.Mockito;
import org.pac4j.core.config.Config;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistryImpl;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import javax.annotation.PostConstruct;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Configuration
@Import( TaraConfiguration.class)
public class TestTaraConfiguration {

    @Bean
    public CentralAuthenticationService centralAuthenticationService() {
        return Mockito.mock(CentralAuthenticationService.class);
    }

    @Bean
    public TaraProperties taraProperties() {
        return Mockito.mock(TaraProperties.class);
    }

    @Bean
    public BuildProperties buildProperties() {
        return Mockito.mock(BuildProperties.class);
    }

    @Bean
    public GitProperties gitProperties() {
        return Mockito.mock(GitProperties.class);
    }

    @Bean
    public ServicesManager servicesManager() {
        return Mockito.mock(ServicesManager.class);
    }

    @Bean
    @Qualifier("oidcPrincipalFactory")
    public PrincipalFactory oidcPrincipalFactory() {return Mockito.mock(PrincipalFactory.class); }

    @Bean
    public OidcAuthorizationRequestSupport authorizationRequestSupport() {
        return Mockito.mock(OidcAuthorizationRequestSupport.class);
    }

    @Bean
    public AuditTrailRecordResolutionPlan auditTrailRecordResolutionPlan() {
        return Mockito.mock(DefaultAuditTrailRecordResolutionPlan.class);
    }
    @Bean("loginFlowRegistry")
    public FlowDefinitionRegistry loginFlowDefinitionRegistry () {
        return Mockito.mock(FlowDefinitionRegistryImpl.class);
    }
    @Bean
    public FlowBuilderServices flowBuilderServices() {
        return Mockito.mock(FlowBuilderServices.class);
    }
    @Bean
    @Qualifier("oauthSecConfig")
    public Config oauthSecConfig() {
        return Mockito.mock(Config.class);
    }
    @Bean
    public TicketRegistry ticketRegistry() {
        return Mockito.mock(TicketRegistry.class);
    }
    @Bean
    public AccessTokenFactory defaultAccessTokenFactory() {
        return Mockito.mock(AccessTokenFactory.class);
    }
    @Bean
    public OAuth20ProfileScopeToAttributesFilter profileScopeToAttributesFilter() {
        return Mockito.mock(OAuth20ProfileScopeToAttributesFilter.class);
    }
    @Bean
    public ServiceFactory<WebApplicationService> webApplicationServiceFactory() {
        return Mockito.mock(ServiceFactory.class);
    }
    @Bean
    public ExpirationPolicy accessTokenExpirationPolicy() {
        return Mockito.mock(ExpirationPolicy.class);
    }
    @Bean
    public OAuth20TokenGenerator oauthTokenGenerator() {
        return Mockito.mock(OAuth20TokenGenerator.class);
    }
    @Bean
    public Collection<BaseAccessTokenGrantRequestExtractor> accessTokenGrantRequestExtractors() {
        return Mockito.mock(Collection.class);
    }
    @Bean
    public Collection<OAuth20TokenRequestValidator> oauthTokenRequestValidators() {
        return Mockito.mock(Collection.class);
    }
    @Bean
    public ObjectProvider<CookieRetrievingCookieGenerator> ticketGrantingTicketCookieGenerator() {
        return Mockito.mock(ObjectProvider.class);
    }
    @Bean
    public OidcIdTokenSigningAndEncryptionService oidcTokenSigningAndEncryptionService() throws Exception {
        LoadingCache<String, Optional<RsaJsonWebKey>> defaultKey = Mockito.mock(LoadingCache.class);
        LoadingCache<OidcRegisteredService, Optional<RsaJsonWebKey>> serviceKey = Mockito.mock(LoadingCache.class);

        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        Mockito.when(defaultKey.get(Mockito.any())).thenReturn(Optional.of(rsaJsonWebKey));
        Mockito.when(serviceKey.get(Mockito.any())).thenReturn(Optional.of(rsaJsonWebKey));

        return new OidcIdTokenSigningAndEncryptionService(defaultKey,
                serviceKey,
                "dummyIssuer");
    }

    @Bean("oAuthCodeIdGenerator")
    public UniqueTicketIdGenerator oAuthCodeIdGenerator() {
        return Mockito.mock(UniqueTicketIdGenerator.class);
    }

    @Bean("defaultOAuthCodeFactory")
    public OAuthCodeFactory defaultOAuthCodeFactory() {
        return Mockito.mock(OAuthCodeFactory.class);
    }

    @Bean("oauthCasAuthenticationBuilder")
    public OAuth20CasAuthenticationBuilder authenticationBuilder() {
        return Mockito.mock(OAuth20CasAuthenticationBuilder.class);
    }

    @Bean("oauthAuthorizationResponseBuilders")
    public Set<OAuth20AuthorizationResponseBuilder> oauthAuthorizationResponseBuilders() {
        return Mockito.mock(Set.class);
    }

    @Bean("oauthAuthorizationRequestValidators")
    public Set<OAuth20AuthorizationRequestValidator> oauthRequestValidators () {
        return Mockito.mock(Set.class);
    }

    @Bean("registeredServiceAccessStrategyEnforcer")
    public AuditableExecution registeredServiceAccessStrategyEnforcer() {
        return Mockito.mock(AuditableExecution.class);
    }

    @Bean("consentApprovalViewResolver")
    public ConsentApprovalViewResolver consentApprovalViewResolver() {
        return Mockito.mock(ConsentApprovalViewResolver.class);
    }

    @Bean("auditTrailExecutionPlan")
    public AuditTrailExecutionPlan auditTrailExecutionPlan() {
        return Mockito.mock(AuditTrailExecutionPlan.class);
    }
}
