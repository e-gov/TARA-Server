package ee.ria.sso.config;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
@ConfigurationProperties("tara")
public class TaraProperties {

    private final CasConfigurationProperties casConfigurationProperties;
    private final Environment environment;
    private Application application = new Application();

    public TaraProperties(CasConfigurationProperties casConfigurationProperties, Environment environment) {
        this.casConfigurationProperties = casConfigurationProperties;
        this.environment = environment;
    }

    public String getApplicationUrl() {
        return this.casConfigurationProperties.getServer().getName();
    }

    public String getApplicationVersion() {
        return this.environment.getProperty("tara.version", "-");
    }

    public String getLocaleUrl(String locale) throws UnsupportedEncodingException {
        String[] uriFragments = this.casConfigurationProperties.getServer().getName().split("://");
        String uri = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("locale", locale).toUriString();
        if ("https".equalsIgnoreCase(uriFragments[0])) {
            uri = String.format("https://%s%s", uriFragments[1], uri.substring(uri.replace("://", "").indexOf("/") + 3));
        }
        return URLDecoder.decode(uri, "UTF-8");
    }

    public String getBackUrl(String pac4jRequestedUrl, Locale locale) throws URISyntaxException {
        if (StringUtils.isNotBlank(pac4jRequestedUrl)) {
            return new URIBuilder(pac4jRequestedUrl).setParameter("lang", locale.getLanguage()).build().toString();
        }
        return "#";
    }

    public Application getApplication() {
        return application;
    }

    public enum Mode {
        development, production
    }

    public static class Application {

        private Mode mode = Mode.production;
        private String digestAlgorithm = "SHA-256";

        public boolean isDevelopment() {
            return Mode.development.equals(this.mode);
        }

        public Mode getMode() {
            return mode;
        }

        public void setMode(Mode mode) {
            this.mode = mode;
        }

        public String getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public void setDigestAlgorithm(String digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
        }

    }

}
