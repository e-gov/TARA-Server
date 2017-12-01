package org.apereo.cas.config;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.handler.support.HttpBasedServiceCredentialsAuthenticationHandler;
import org.apereo.cas.authentication.handler.support.JaasAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.ProxyingPrincipalResolver;
import org.apereo.cas.authentication.support.password.PasswordPolicyConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.http.HttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import ee.ria.sso.authentication.TaraAuthenticationHandler;
import ee.ria.sso.authentication.principal.TaraPrincipalFactory;
import ee.ria.sso.authentication.principal.TaraPrincipalResolver;

/**
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

@Configuration("casCoreAuthenticationHandlersConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasCoreAuthenticationHandlersConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("supportsTrustStoreSslSocketFactoryHttpClient")
    private HttpClient supportsTrustStoreSslSocketFactoryHttpClient;

    @Autowired(required = false)
    @Qualifier("acceptPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration acceptPasswordPolicyConfiguration;

    @Autowired(required = false)
    @Qualifier("jaasPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration jaasPasswordPolicyConfiguration;

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    @ConditionalOnMissingBean(name = "jaasPrincipalFactory")
    @Bean
    public PrincipalFactory jaasPrincipalFactory() {
        return new TaraPrincipalFactory();
    }

    @Bean
    public AuthenticationHandler proxyAuthenticationHandler() {
        return new HttpBasedServiceCredentialsAuthenticationHandler(null, servicesManager,
            proxyPrincipalFactory(), Integer.MIN_VALUE, supportsTrustStoreSslSocketFactoryHttpClient);
    }

    @ConditionalOnMissingBean(name = "proxyPrincipalFactory")
    @Bean
    public PrincipalFactory proxyPrincipalFactory() {
        return new TaraPrincipalFactory();
    }

    @ConditionalOnMissingBean(name = "proxyPrincipalResolver")
    @Bean
    public PrincipalResolver proxyPrincipalResolver() {
        return new ProxyingPrincipalResolver(proxyPrincipalFactory());
    }

    @RefreshScope
    @Bean
    public AuthenticationHandler taraAuthenticationHandler() {
        return new TaraAuthenticationHandler(this.servicesManager, this.taraPrincipalFactory(), null);
    }

    @ConditionalOnMissingBean(name = "taraPrincipalFactory")
    @Bean
    public PrincipalFactory taraPrincipalFactory() {
        return new TaraPrincipalFactory();
    }

    /**
     * The type Proxy authentication event execution plan configuration.
     */
    @Configuration("proxyAuthenticationEventExecutionPlanConfiguration")
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    public class ProxyAuthenticationEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {

        @Override
        public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
            plan.registerAuthenticationHandlerWithPrincipalResolver(proxyAuthenticationHandler(), proxyPrincipalResolver());
        }

    }

    /**
     * The type Jaas authentication event execution plan configuration.
     */
    @Configuration("jaasAuthenticationEventExecutionPlanConfiguration")
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    public class JaasAuthenticationEventExecutionPlanConfiguration
        implements AuthenticationEventExecutionPlanConfigurer {

        @Autowired
        private TaraPrincipalResolver taraPrincipalResolver;

        @ConditionalOnMissingBean(name = "jaasAuthenticationHandlers")
        @RefreshScope
        @Bean
        public List<AuthenticationHandler> jaasAuthenticationHandlers() {
            return casProperties.getAuthn().getJaas()
                .stream()
                .filter(jaas -> StringUtils.isNotBlank(jaas.getRealm()))
                .map(jaas -> {
                    final JaasAuthenticationHandler h =
                        new JaasAuthenticationHandler(jaas.getName(),
                            servicesManager, jaasPrincipalFactory(), null);

                    h.setKerberosKdcSystemProperty(jaas.getKerberosKdcSystemProperty());
                    h.setKerberosRealmSystemProperty(jaas.getKerberosRealmSystemProperty());
                    h.setRealm(jaas.getRealm());
                    h.setPasswordEncoder(Beans.newPasswordEncoder(jaas.getPasswordEncoder()));

                    if (jaasPasswordPolicyConfiguration != null) {
                        h.setPasswordPolicyConfiguration(jaasPasswordPolicyConfiguration);
                    }
                    h.setPrincipalNameTransformer(Beans.newPrincipalNameTransformer(
                        jaas.getPrincipalTransformation()));
                    h.setCredentialSelectionPredicate(Beans.newCredentialSelectionPredicate(
                        jaas.getCredentialCriteria()));
                    return h;
                })
                .collect(Collectors.toList());
        }

        @Override
        public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
            plan.registerAuthenticationHandlerWithPrincipalResolvers(jaasAuthenticationHandlers(), this.taraPrincipalResolver);
        }

    }

}
