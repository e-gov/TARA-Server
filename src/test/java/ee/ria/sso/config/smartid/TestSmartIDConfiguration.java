package ee.ria.sso.config.smartid;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties
@ComponentScan(basePackages = { "ee.ria.sso.config.smartid" })
@Configuration
public class TestSmartIDConfiguration {
}