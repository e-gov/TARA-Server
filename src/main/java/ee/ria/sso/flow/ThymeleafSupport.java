package ee.ria.sso.flow;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.service.manager.ManagerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.OidcRegisteredService;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Slf4j
@AllArgsConstructor
public class ThymeleafSupport {

    private final ManagerService managerService;
    private final CasConfigurationProperties casProperties;
    private final TaraProperties taraProperties;
    private final String defaultLocaleChangeParam;

    public boolean isAuthMethodAllowed(final AuthenticationType method) {
        if (method == null)
            return false;

        SharedAttributeMap<Object> sessionMap = RequestContextHolder.getRequestContext().getExternalContext().getSessionMap();
        final List<AuthenticationType> clientSpecificAuthMethodList = sessionMap.get(Constants.TARA_OIDC_SESSION_AUTH_METHODS, List.class);

        if (clientSpecificAuthMethodList != null) {
            return clientSpecificAuthMethodList.contains(method);
        } else {
            return true; // client specific auth method list is not supported (ie cas-management)
        }
    }

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getLocaleUrl(String locale) throws URISyntaxException {
        try {
            UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam(defaultLocaleChangeParam, locale);
            URI serverUri = new URI(this.casProperties.getServer().getName());
            if ("https".equalsIgnoreCase(serverUri.getScheme())) {
                builder.port((serverUri.getPort() == -1) ? 443 : serverUri.getPort());
            }
            return builder.scheme(serverUri.getScheme()).host(serverUri.getHost()).build(true).toUriString();
        } catch (Exception e) {
            log.warn("Failed to create the locale change URL: " + e.getMessage(), e);
            return "#";
        }
    }

    public boolean isEidasOnlyDirect(Map<String, Object> sessionAttributes) {
        return isOpenIDAndEidasOnlyScopePresent(sessionAttributes) && isEidasCountryScopePresent(sessionAttributes);
    }

    private boolean isOpenIDAndEidasOnlyScopePresent(Map<String, Object> sessionAttributes) {
        Object sessionScopes = sessionAttributes.get(Constants.TARA_OIDC_SESSION_SCOPES);
        if (sessionScopes != null) {
            List<TaraScope> scopes = (List<TaraScope>) sessionScopes;
            return scopes.contains(TaraScope.OPENID) && scopes.contains(TaraScope.EIDASONLY);
        }

        return false;
    }

    private boolean isEidasCountryScopePresent(Map<String, Object> session) {
        Object eidasCountry = session.get(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        return eidasCountry != null;
    }

    public String getBackUrl(String url, Locale locale) throws URISyntaxException {
        if (StringUtils.isNotBlank(url)) {
            return new URIBuilder(url).setParameter(defaultLocaleChangeParam, locale.getLanguage()).build().toString();
        }
        return "#";
    }

    public String getHomeUrl() {
        final Object redirectUri = RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .get(Constants.TARA_OIDC_SESSION_REDIRECT_URI);

        return getHomeUrl(redirectUri == null ? null : (String) redirectUri);
    }

    public String getHomeUrl(String redirectUri) {
        if (StringUtils.isNotBlank(redirectUri)) {
            return this.managerService.getServiceByID(redirectUri)
                    .orElse(new OidcRegisteredService() {
                        @Override
                        public String getInformationUrl() {
                            return "#";
                        }
                    })
                    .getInformationUrl();
        } else {
            log.debug("Could not find home url from session");
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
