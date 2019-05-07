package ee.ria.sso.flow;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.service.manager.ManagerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.OidcRegisteredService;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

@Slf4j
@AllArgsConstructor
public class ThymeleafSupport {

    private final ManagerService managerService;
    private final CasConfigurationProperties casProperties;
    private final TaraProperties taraProperties;
    private final String defaultLocaleChangeParam;

    public boolean isAuthMethodAllowed(final AuthenticationType method) {
        if (method != null && taraProperties.isPropertyEnabled(method.getPropertyName() + ".enabled")) {
            final Object attribute = RequestContextHolder.getRequestContext().getExternalContext()
                    .getSessionMap().get(Constants.TARA_OIDC_SESSION_AUTH_METHODS);

            if (attribute == null) {
                return true; // TODO: only needed for cas management
            } else if (attribute instanceof List) {
                return ((List) attribute).contains(method);
            }
        }

        return false;
    }

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getLocaleUrl(String locale) throws URISyntaxException {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam(defaultLocaleChangeParam, locale);
        URI serverUri = new URI(this.casProperties.getServer().getName());
        if ("https".equalsIgnoreCase(serverUri.getScheme())) {
            builder.port((serverUri.getPort() == -1) ? 443 : serverUri.getPort());
        }
        return builder.scheme(serverUri.getScheme()).host(serverUri.getHost()).build(true).toUriString();
    }

    public String getBackUrl(String url, Locale locale) throws URISyntaxException {
        if (StringUtils.isNotBlank(url)) {
            return new URIBuilder(url).setParameter(defaultLocaleChangeParam, locale.getLanguage()).build().toString();
        }
        return "#";
    }

    public String getHomeUrl() {
        final Object redirectUri = RequestContextHolder.getRequestContext().getExternalContext()
                .getSessionMap().get(Constants.TARA_OIDC_SESSION_REDIRECT_URI);

        if (redirectUri instanceof String) {
            return this.managerService.getServiceByID((String) redirectUri)
                    .orElse(new OidcRegisteredService() {
                        @Override
                        public String getInformationUrl() {
                            return "#";
                        }
                    })
                    .getInformationUrl();
        } else {
            log.error("Could not find home url from session");
            return "#";
        }
    }

    public String getCurrentRequestIdentifier(HttpServletRequest request) {
        try {
            return (String)request.getAttribute(Constants.MDC_ATTRIBUTE_REQUEST_ID);
        } catch (Exception e) {
            log.error("Failed to retrieve current request identifier!", e);
            return null;
        }
    }

    public String getTestEnvironmentAlertMessageIfAvailable() {
        return taraProperties.getTestEnvironmentWarningMessage();
    }
}
