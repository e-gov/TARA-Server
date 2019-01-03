package ee.ria.sso.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.discovery.OidcServerDiscoverySettings;

import java.util.List;

@Slf4j
@Getter
@Setter
public class TaraOidcServerDiscoverySettings extends OidcServerDiscoverySettings {

    @JsonProperty("ui_locales_supported")
    private List<String> uiLocalesSupported;

    public TaraOidcServerDiscoverySettings(final CasConfigurationProperties casProperties, final String issuer) {
        super(casProperties, issuer);
    }
}
