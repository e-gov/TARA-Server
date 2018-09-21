package ee.ria.sso.config.idcard;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.constraints.Min;
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

    private boolean ocspEnabled = true;

    private String ocspUrl;
    private String ocspCertificateLocation;
    private List<String> ocspCertificates = new ArrayList<>();

    @Min(0L)
    private long ocspAcceptedClockSkew = 2L;

    @Min(0L)
    private long ocspResponseLifetime = 900L;

    @PostConstruct
    public void validateConfiguration() {
        if (this.ocspEnabled) {
            Assert.notNull(this.ocspUrl, "OCSP URL cannot be missing!");
            Assert.notNull(this.ocspCertificateLocation, "OCSP certificates location cannot be missing!");
            Assert.notEmpty(this.ocspCertificates, "List of OCSP certificates cannot be empty!");
        }
    }

}
