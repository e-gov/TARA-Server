package ee.ria.sso.config.smartid;

import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.flow.action.SmartIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.SmartIDStartAuthenticationAction;
import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.service.manager.ManagerServiceImpl;
import ee.ria.sso.statistics.StatisticsHandler;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.DefaultServicesManager;
import org.apereo.cas.services.ServicesManager;
import org.mockito.Mockito;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.smartid",
        "ee.ria.sso.service.smartid"
})
@Configuration
@Import(value = {
        SmartIDCheckAuthenticationAction.class,
        SmartIDStartAuthenticationAction.class,
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class,

})
public class TestSmartIDConfiguration {

    @Bean
    public ThymeleafSupport thymeleafSupport() {
        return Mockito.mock(ThymeleafSupport.class);
    }
}