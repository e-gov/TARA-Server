package ee.ria.sso.flow;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.utils.RedirectUrlUtil;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
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
import java.net.URLEncoder;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

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
        final String redirectUri = RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .getString(Constants.TARA_OIDC_SESSION_REDIRECT_URI);

        final String clientId = RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .getString(Constants.TARA_OIDC_SESSION_CLIENT_ID);

        String informationUrl = getHomeUrl(clientId);

        if (StringUtils.isNotBlank(informationUrl)) {
            return informationUrl;
        }

        return getUserCancelUrl(redirectUri);
    }

    public String getHomeUrl(String clientId) {
        if (StringUtils.isNotBlank(clientId)) {
            return this.managerService.getServiceByName(clientId)
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

    public String getUserCancelUrl(String redirectUri) {
        final String sessionState = RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .getString(Constants.TARA_OIDC_SESSION_STATE);

        return getUserCancelUrl(redirectUri, sessionState);
    }

    @SneakyThrows
    public String getUserCancelUrl(String redirectUri, String sessionState) {
        return RedirectUrlUtil.createRedirectUrl(redirectUri, "user_cancel", "User canceled the login process", sessionState);
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
