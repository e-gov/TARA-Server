package ee.ria.sso.config.eidas;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConditionalOnProperty("eidas.enabled")
@Configuration
@ConfigurationProperties(prefix = "eidas")
@Validated
@Getter
@Setter
public class EidasConfigurationProvider {

    private String serviceUrl = "http://localhost:8889";
    private String heartbeatUrl;
    private String availableCountries;

}
