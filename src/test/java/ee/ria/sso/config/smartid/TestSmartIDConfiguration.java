package ee.ria.sso.config.smartid;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.cas.CasConfigProperties;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.flow.action.SmartIDCheckAuthenticationAction;
import ee.ria.sso.flow.action.SmartIDCheckCancelAction;
import ee.ria.sso.flow.action.SmartIDStartAuthenticationAction;
import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.statistics.StatisticsHandler;
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
        SmartIDStartAuthenticationAction.class,
        SmartIDCheckAuthenticationAction.class,
        SmartIDCheckCancelAction.class,
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class,

})
public class TestSmartIDConfiguration {

    @Bean
    public ThymeleafSupport thymeleafSupport() {
        return Mockito.mock(ThymeleafSupport.class);
    }

    @Bean
    public ManagerService managerService() {
        return Mockito.mock(ManagerService.class);
    }

    @Bean
    public CasConfigProperties casConfigurationProvider() {
        return Mockito.mock(CasConfigProperties.class);
    }
}
