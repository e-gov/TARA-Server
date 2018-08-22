package ee.ria.sso.config.idcard;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

@Component
@ConditionalOnProperty("id-card.enabled")
@Configuration
@ConfigurationProperties(prefix = "id-card")
@Validated
@Getter
@Setter
public class IDCardConfigurationProvider {

    private boolean ocspEnabled;

    private String ocspUrl = "http://demo.sk.ee/ocsp";
    private String ocspCertificateLocation;
    private List<String> ocspCertificates = new ArrayList<>();

}
