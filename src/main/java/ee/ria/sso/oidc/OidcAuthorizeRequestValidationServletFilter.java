package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@AllArgsConstructor
public class OidcAuthorizeRequestValidationServletFilter implements Filter {

    private final OidcAuthorizeRequestValidator oidcAuthorizeRequestValidator;


    private final EidasConfigurationProvider eidasConfigurationProvider;

    private final TaraProperties taraProperties;

    @Override
    public void init(FilterConfig filterConfig) {
        log.debug("Initialize filter: {}", OidcAuthorizeRequestValidationServletFilter.class.getName());
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            this.oidcAuthorizeRequestValidator.validateAuthenticationRequestParameters(request);
            this.saveOidcRequestParametersToSession(request);

            filterChain.doFilter(servletRequest, servletResponse);
        } catch (OidcAuthorizeRequestValidator.InvalidRequestException e) {
            log.error("Invalid OIDC authorization request: " + e.getMessage());
            if (isInvalidClient(e)) {
                throw new IllegalStateException("Invalid authorization request, cannot redirect", e);
            } else {
                response.sendRedirect(getRedirectUrlToRelyingParty(request, e));
            }
        }
    }

    private boolean isInvalidClient(OidcAuthorizeRequestValidator.InvalidRequestException e) {
        return e.getInvalidParameter() == OidcAuthorizeRequestParameter.REDIRECT_URI || e.getInvalidParameter() == OidcAuthorizeRequestParameter.CLIENT_ID;
    }

    private String getRedirectUrlToRelyingParty(HttpServletRequest request, OidcAuthorizeRequestValidator.InvalidRequestException e) {
        String redirectUri = request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey());
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(redirectUri);
            sb.append(redirectUri.contains("?") ? "&" : "?");
            sb.append(String.format("error=%s", URLEncoder.encode(e.getErrorCode(), UTF_8.name())));
            sb.append(String.format("&error_description=%s", URLEncoder.encode(e.getErrorDescription(), UTF_8.name())));
            String state = request.getParameter(OidcAuthorizeRequestParameter.STATE.getParameterKey());
            if (StringUtils.isNotBlank(state)) {
                sb.append(String.format("&state=%s", URLEncoder.encode(state, UTF_8.name())));
            }

            return sb.toString();
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void saveOidcRequestParametersToSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);

        String[] scopeElements = getScopeElements(request);
        List<TaraScope> scopes = parseScopes(scopeElements);
        session.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, scopes);

        if (eidasConfigurationProvider != null) {
            session.setAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY, parseScopeEidasCountry(scopeElements).orElse(null));
        }

        session.setAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID,
                request.getParameter(OidcAuthorizeRequestParameter.CLIENT_ID.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI,
                request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey())
        );

        List<AuthenticationType> authenticationMethodsList = getListOfAllowedAuthenticationMethods(scopes);
        log.debug("List of authentication methods to display on login page: {}", authenticationMethodsList);
        session.setAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS,
                authenticationMethodsList
        );

        final String acrValues = request.getParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey());
        if (acrValues != null) session.setAttribute(Constants.TARA_OIDC_SESSION_LOA,
                LevelOfAssurance.findByAcrName(acrValues));
    }

    private String[] getScopeElements(HttpServletRequest request) {
        String scopeParameter = request.getParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey());
        if (StringUtils.isBlank(scopeParameter)) {
            return new String[0];
        }
        return scopeParameter.split(" ");
    }

    private List<TaraScope> parseScopes(String[] scopeElements) {
        return Arrays.stream(scopeElements)
                .map(scopeElement -> {
                    try {
                        return TaraScope.getScope(scopeElement);
                    } catch (IllegalArgumentException e) {
                        log.warn("Invalid scope value '{}', entry ignored!", scopeElement);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private Optional<TaraScopeValuedAttribute> parseScopeEidasCountry(String[] scopeElements) {
        return Arrays.stream(scopeElements)
                .filter(eidasConfigurationProvider.getAllowedEidasCountryScopeAttributes()::contains)
                .map(this::constructValuedScopeAttribute)
                .filter(Objects::nonNull)
                .findFirst();
    }

    private TaraScopeValuedAttribute constructValuedScopeAttribute(String scopeElement) {
        int lastIndexOf = scopeElement.lastIndexOf(":");
        String scopeAttributeFormalName = scopeElement.substring(0, lastIndexOf);
        String scopeAttributeValue = scopeElement.substring(lastIndexOf + 1);

        TaraScopeValuedAttribute scopeAttribute = null;
        if (StringUtils.isNotBlank(scopeAttributeValue)) {
            scopeAttribute = TaraScopeValuedAttribute.builder()
                    .name(TaraScopeValuedAttributeName.getByFormalName(scopeAttributeFormalName))
                    .value(scopeAttributeValue)
                    .build();
        }
        return scopeAttribute;
    }

    private List<AuthenticationType> getListOfAllowedAuthenticationMethods(final List<TaraScope> scopes) {
        if (scopes.contains(TaraScope.EIDASONLY)) {
            return Arrays.asList(AuthenticationType.eIDAS);
        } else if (isAuthMethodSpecificScopePresent(scopes)) {
            return Arrays.stream(AuthenticationType.values())
                    .filter(e -> scopes.contains(e.getScope()) )
                    .collect(Collectors.toList());
        } else {
            return taraProperties.getDefaultAuthenticationMethods();
        }
    }

    private boolean isAuthMethodSpecificScopePresent(List<TaraScope> scopes) {
        return !Collections.disjoint(scopes, TaraScope.SUPPORTS_AUTHENTICATION_METHOD_SELECTION);
    }

    @Override
    public void destroy() {
        log.debug("Destroy filter: {}", OidcAuthorizeRequestValidationServletFilter.class.getName());
    }

}
