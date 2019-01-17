package ee.ria.sso.oidc;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.sso.Constants;
import ee.ria.sso.config.TaraProperties;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.discovery.OidcServerDiscoverySettings;
import org.apereo.cas.support.oauth.OAuth20Constants;

import java.util.List;

@Slf4j
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class TaraOidcServerDiscoverySettings extends OidcServerDiscoverySettings {

    @JsonProperty("ui_locales_supported")
    private List<String> uiLocalesSupported;

    @JsonIgnore
    private TaraProperties taraProperties;

    public TaraOidcServerDiscoverySettings(final TaraProperties taraProperties, final CasConfigurationProperties casProperties, final String issuer) {
        super(casProperties, issuer);
        this.taraProperties = taraProperties;
    }

    @Override
    @JsonProperty("token_endpoint")
    public String getTokenEndpoint() {
        return super.getServerPrefix().concat('/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.TOKEN_URL);
    }

    @Override
    public String getRegistrationEndpoint() {
        if (taraProperties.isPropertyEnabled(Constants.TARA_OIDC_DYNAMIC_CLIENT_REGISTRATION_ENDPOINT_ENABLED)) {
            return super.getRegistrationEndpoint();
        } else {
            return null;
        }
    }

    @Override
    public String getIntrospectionEndpoint() {
       if (taraProperties.isPropertyEnabled(Constants.TARA_OIDC_INTROSPECTION_ENDPOINT_ENABLED)) {
            return super.getIntrospectionEndpoint();
       } else {
            return null;
       }
    }

    @Override
    public List<String> getIntrospectionSupportedAuthenticationMethods() {
        if (taraProperties.isPropertyEnabled(Constants.TARA_OIDC_INTROSPECTION_ENDPOINT_ENABLED)) {
            return super.getIntrospectionSupportedAuthenticationMethods();
        } else {
            return null;
        }
    }

    @Override
    public String getRevocationEndpoint() {
        if (taraProperties.isPropertyEnabled(Constants.TARA_OIDC_REVOCATION_ENDPOINT_ENABLED)) {
            return super.getRevocationEndpoint();
        } else {
            return null;
        }
    }

    @Override
    public String getUserinfoEndpoint() {
        if (taraProperties.isPropertyEnabled(Constants.TARA_OIDC_PROFILE_ENDPOINT_ENABLED)) {
            return super.getUserinfoEndpoint();
        } else {
            return null;
        }
    }

    @Override
    public String getEndSessionEndpoint() {
        return null;
    }
}
