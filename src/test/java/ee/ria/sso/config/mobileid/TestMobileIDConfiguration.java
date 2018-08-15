package ee.ria.sso.config.mobileid;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.service.mobileid.MobileIDAuthenticatorWrapper;
import ee.ria.sso.statistics.StatisticsHandler;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.mobileid",
        "ee.ria.sso.service.mobileid"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class
})
public class TestMobileIDConfiguration {

    @Bean
    @Primary
    @ConditionalOnProperty("mobile-id.enabled")
    MobileIDAuthenticatorWrapper mockMobileIDAuthenticatorWrapper() {
        MobileIDAuthenticatorWrapper mobileIDAuthenticator = Mockito.mock(MobileIDAuthenticatorWrapper.class);
        return mobileIDAuthenticator;
    }

}
