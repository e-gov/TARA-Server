package ee.ria.sso.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config",
        "ee.ria.sso.security"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class
})
public class TestTaraCspConfiguration {
}
