package ee.ria.sso.config;

import ee.ria.sso.model.EmptyOidcRegisteredService;
import ee.ria.sso.service.manager.ManagerService;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.core.collection.ParameterMap;
import org.springframework.webflow.execution.RequestContextHolder;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
@ConfigurationProperties("tara")
public class TaraProperties {

    private final Logger log = LoggerFactory.getLogger(TaraProperties.class);

    private final CasConfigurationProperties casConfigurationProperties;
    private final Environment environment;
    private final ManagerService managerService;
    private Application application = new Application();

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    public TaraProperties(CasConfigurationProperties casConfigurationProperties, Environment environment, ManagerService managerService) {
        this.casConfigurationProperties = casConfigurationProperties;
        this.environment = environment;
        this.managerService = managerService;
    }

    public String getApplicationUrl() {
        return this.casConfigurationProperties.getServer().getName();
    }

    public String getApplicationVersion() {
        return this.environment.getProperty("tara.version", "-");
    }

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getLocaleUrl(String locale) throws URISyntaxException {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("locale", locale);
        RequestAttributes attributes = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            int statusCode = ((ServletRequestAttributes) attributes).getResponse().getStatus();
            switch (statusCode) {
                case 200:
                    break;
                case 404:
                    builder.replacePath(Integer.toString(statusCode));
                    break;
                default:
                    builder.replacePath("error");
            }
        }
        URI serverUri = new URI(this.casConfigurationProperties.getServer().getName());
        if ("https".equalsIgnoreCase(serverUri.getScheme())) {
            builder.port((serverUri.getPort() == -1) ? 443 : serverUri.getPort());
        }
        return builder.scheme(serverUri.getScheme()).host(serverUri.getHost()).build(true).toUriString();
    }

    public String getBackUrl(String pac4jRequestedUrl, Locale locale) throws URISyntaxException {
        if (StringUtils.isNotBlank(pac4jRequestedUrl)) {
            return new URIBuilder(pac4jRequestedUrl).setParameter("lang", locale.getLanguage()).build().toString();
        }
        return "#";
    }

    public String getHomeUrl() {
        ParameterMap map = RequestContextHolder.getRequestContext().getRequestParameters();
        if (map.contains("service")) {
            Optional<NameValuePair> uri;
            try {
                uri = new URIBuilder(URLDecoder.decode(map.getRequired("service"), StandardCharsets.UTF_8.name())).
                        getQueryParams().stream().filter(p -> p.getName().equals("redirect_uri")).findFirst();
            } catch (URISyntaxException | UnsupportedEncodingException e) {
                log.error("Failed to parse home url", e);
                uri = Optional.empty();
            }
            if (uri.isPresent()) {
                return this.managerService.getServiceByID(uri.get().getValue()).orElse(new EmptyOidcRegisteredService()).
                        getInformationUrl();
            }
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

    public Environment getEnvironment() {
        return environment;
    }

    public String getTestEnvironmentAlertMessageIfAvailable() {
        return this.environment.getProperty("env.test.message", (String) null);
    }
}
