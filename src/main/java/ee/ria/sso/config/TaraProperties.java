package ee.ria.sso.config;

import lombok.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;

@Data
@ConfigurationProperties("tara")
public class TaraProperties {

    private String digestAlgorithm = "SHA-256";

    @Value("${oidc.authorize.force-auth-renewal.enabled:true}")
    private boolean forceOidcAuthenticationRenewalEnabled;

    @Value("${env.test.message}")
    private String testEnvironmentWarningMessage;

    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    private final Environment environment;

    public boolean isPropertyEnabled(final String propertyName) {
        return StringUtils.isNotBlank(propertyName) && "true".equals(
                this.environment.getProperty(propertyName, (String) null)
        );
    }
}
