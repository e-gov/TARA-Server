package ee.ria.sso.config;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties("tara")
public class TaraProperties {

    private String digestAlgorithm = "SHA-256";

    @Value("${oidc.authorize.force-auth-renewal.enabled:true}")
    private boolean forceOidcAuthenticationRenewalEnabled;

    @Value("${env.test.message:#{null}}")
    private String testEnvironmentWarningMessage;

    @Value("${tara.cache-control-header:'public,max-age=43200'}") // Default: 12h
    private String cacheControlHeader;

    private Map<AuthenticationType, LevelOfAssurance> authenticationMethodsLoaMap;

    private List<AuthenticationType> defaultAuthenticationMethods = Arrays.asList(
            AuthenticationType.IDCard,
            AuthenticationType.MobileID);

    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    private final Environment environment;

    @PostConstruct
    public void validateConfiguration() {
        if (authenticationMethodsLoaMap != null && authenticationMethodsLoaMap.containsKey(AuthenticationType.eIDAS))
            throw new IllegalStateException("Please check your configuration! Level of assurance (LoA) cannot be configured for eIDAS authentication method! NB! The proper LoA for eIDAS authentication is determined from the eIDAS authentication response directly.");

    }

    public boolean isPropertyEnabled(final String propertyName) {
        return StringUtils.isNotBlank(propertyName) && "true".equals(
                this.environment.getProperty(propertyName, (String) null)
        );
    }
}
