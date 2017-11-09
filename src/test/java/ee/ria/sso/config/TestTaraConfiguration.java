package ee.ria.sso.config;

import javax.annotation.PostConstruct;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Configuration
@Import(TaraConfiguration.class)
public class TestTaraConfiguration {

    private final TaraProperties taraProperties;

    public TestTaraConfiguration(TaraProperties taraProperties) {
        this.taraProperties = taraProperties;
    }

    @PostConstruct
    protected void init() {
        this.taraProperties.getEnvironment().setMode(TaraProperties.Mode.development);
    }

}
