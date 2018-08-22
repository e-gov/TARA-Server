package ee.ria.sso.statistics;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.statistics"
})
@Configuration
@Import(value = {
        TaraStatHandler.class
})
public class TestTaraStatHandler {
}
