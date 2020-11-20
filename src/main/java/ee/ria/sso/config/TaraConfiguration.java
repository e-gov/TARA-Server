package ee.ria.sso.config;

import ee.ria.sso.authentication.TaraAuthenticationHandler;
import ee.ria.sso.authentication.principal.TaraPrincipalFactory;
import ee.ria.sso.config.cas.CasConfigProperties;
import ee.ria.sso.flow.TaraWebflowConfigurer;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.i18n.TaraLocaleChangeInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowExecutionPlan;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Slf4j
@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)
@ComponentScan(basePackages = {"ee.ria.sso"})
@EnableConfigurationProperties(TaraProperties.class)
public class TaraConfiguration extends WebMvcConfigurerAdapter {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Bean
    public PrincipalFactory taraPrincipalFactory() {
        return new TaraPrincipalFactory();
    }

    @Bean
    public ThymeleafSupport thymeleafSupport(CasConfigurationProperties casProperties, TaraProperties taraProperties) {
        return new ThymeleafSupport(casProperties, taraProperties, getDefaultLocaleChangeParam());
    }

    @Bean
    public CasConfigProperties casConfigurationProvider() {
        return new CasConfigProperties();
    }

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver bean = new SessionLocaleResolver();
        String locale = this.casProperties.getLocale().getDefaultValue();
        this.log.info("Setting default locale to [{}]", locale);
        bean.setDefaultLocale(new Locale(locale));
        return bean;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        TaraLocaleChangeInterceptor localeInterceptor = new TaraLocaleChangeInterceptor();
        localeInterceptor.setIgnoreInvalidLocale(true);
        List<String> names = Arrays.asList(casProperties.getLocale().getParamName().split(","))
                .stream()
                .map(String::trim).collect(Collectors.toList());
        localeInterceptor.setParamNames(names);
        log.info("Supported locale parameters: " + Arrays.asList(localeInterceptor.getParamNames()));
        return localeInterceptor;
    }

    private String getDefaultLocaleChangeParam() {
        Optional<String> localeParam = Arrays.asList(casProperties.getLocale().getParamName().split(",")).stream().findFirst();
        return localeParam.isPresent() ? localeParam.get() : TaraLocaleChangeInterceptor.DEFAULT_OIDC_LOCALE_PARAM;
    }

    @Configuration("TaraWebFlowConfiguration")
    public class TaraWebFlowConfiguration implements CasWebflowExecutionPlanConfigurer {

        @Autowired
        @Qualifier("loginFlowRegistry")
        private FlowDefinitionRegistry loginFlowDefinitionRegistry;

        @Autowired
        private FlowBuilderServices flowBuilderServices;

        @Autowired
        private ApplicationContext applicationContext;


        @Bean("defaultWebflowConfigurer")
        public CasWebflowConfigurer defaultWebflowConfigurer() {
            CasWebflowConfigurer configurer = new TaraWebflowConfigurer(flowBuilderServices, loginFlowDefinitionRegistry,
                    applicationContext, casProperties);
            ((TaraWebflowConfigurer) configurer).setOrder(1);
            return configurer;
        }

        @Override
        public void configureWebflowExecutionPlan(final CasWebflowExecutionPlan plan) {
            plan.registerWebflowConfigurer(defaultWebflowConfigurer());
        }
    }

    @Configuration("TaraAuthenticationEventExecutionPlanConfiguration")
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    public class TaraAuthenticationEventExecutionPlanConfiguration
            implements AuthenticationEventExecutionPlanConfigurer {

        @Autowired
        @Qualifier("servicesManager")
        private ServicesManager servicesManager;

        @Autowired
        @Qualifier("taraPrincipalFactory")
        private PrincipalFactory taraPrincipalFactory;

        @Autowired
        private TaraProperties taraProperties;

        @Bean
        public AuthenticationHandler taraAuthenticationHandler() {
            return new TaraAuthenticationHandler(this.servicesManager, taraPrincipalFactory, 1, taraProperties);
        }

        @Override
        public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
            log.info("Authentication Execution Plan of RIIGI INFOSÜSTEEMI AMET has been loaded");

            plan.registerAuthenticationHandlerWithPrincipalResolver(taraAuthenticationHandler(), null);
        }
    }
}
