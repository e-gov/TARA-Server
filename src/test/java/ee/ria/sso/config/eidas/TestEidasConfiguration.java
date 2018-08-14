package ee.ria.sso.config.eidas;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.statistics.StatisticsHandler;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.eidas",
        "ee.ria.sso.service.eidas"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class
})
public class TestEidasConfiguration {
}
