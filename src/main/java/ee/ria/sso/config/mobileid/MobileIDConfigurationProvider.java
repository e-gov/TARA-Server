package ee.ria.sso.config.mobileid;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConditionalOnProperty("mobile-id.enabled")
@Configuration
@ConfigurationProperties(prefix = "mobile-id")
@Validated
@Getter
@Setter
public class MobileIDConfigurationProvider {

    private String countryCode = "EE";
    private String language = "EST";
    private String serviceName = "Testimine";
    private String messageToDisplay = "";
    private String serviceUrl = "https://tsp.demo.sk.ee";

}
