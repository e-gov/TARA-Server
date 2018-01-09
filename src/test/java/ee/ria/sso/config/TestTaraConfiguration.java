package ee.ria.sso.config;

import javax.annotation.PostConstruct;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import ee.ria.sso.test.TestServicesManager;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Configuration
@Import(TaraConfiguration.class)
public class TestTaraConfiguration {

    @Autowired
    private TaraProperties taraProperties;

    @Bean
    public CasConfigurationProperties casConfigurationProperties() {
        return new CasConfigurationProperties();
    }

    @Bean
    public ServicesManager testServicesManager() {
        return new TestServicesManager();
    }

    @PostConstruct
    protected void init() {
        this.taraProperties.getApplication().setMode(TaraProperties.Mode.development);
    }

}
