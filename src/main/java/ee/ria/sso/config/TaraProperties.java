package ee.ria.sso.config;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
@ConfigurationProperties("tara")
public class TaraProperties {

    private final CasConfigurationProperties casConfigurationProperties;
    private Environment environment = new Environment();

    public TaraProperties(CasConfigurationProperties casConfigurationProperties) {
        this.casConfigurationProperties = casConfigurationProperties;
    }

    public String getApplicationUrl() {
        return this.casConfigurationProperties.getServer().getName();
    }

    public String getLocaleUrl(String locale) throws UnsupportedEncodingException {
        String[] uriFragments = this.casConfigurationProperties.getServer().getName().split("://");
        String uri = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("locale", locale).toUriString();
        if ("https".equalsIgnoreCase(uriFragments[0])) {
            uri = String.format("https://%s%s", uriFragments[1], uri.substring(uri.replace("://", "").indexOf("/") + 3));
        }
        return URLDecoder.decode(uri, "UTF-8");
    }

    public Environment getEnvironment() {
        return environment;
    }

    public enum Mode {
        development, production
    }

    public static class Environment {

        private Mode mode = Mode.production;

        public boolean isDevelopment() {
            return Mode.development.equals(this.mode);
        }

        public Mode getMode() {
            return mode;
        }

        public void setMode(Mode mode) {
            this.mode = mode;
        }

    }

}
