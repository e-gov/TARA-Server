package ee.ria.sso.config.idcard;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.statistics.StatisticsHandler;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.idcard",
        "ee.ria.sso.service.idcard"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class
})
public class TestIDCardConfiguration {
}
