package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.utils.RedirectUrlUtil;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static ee.ria.sso.authentication.AuthenticationType.eIDAS;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.util.CollectionUtils.isEmpty;

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

    private void saveOidcRequestParametersToSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);

        String[] allScopes = getScopeElements(request);
        List<TaraScope> taraScopes = getTaraScopes(session, allScopes);

        if (eidasConfigurationProvider != null) {
            session.setAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY, parseScopeEidasCountry(allScopes).orElse(null));
        }

        session.setAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID,
                request.getParameter(OidcAuthorizeRequestParameter.CLIENT_ID.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI,
                request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_STATE,
                request.getParameter(OidcAuthorizeRequestParameter.STATE.getParameterKey()));

        LevelOfAssurance requestedLoa = getLevelOfAssurance(request);
        if (requestedLoa != null) {
            session.setAttribute(Constants.TARA_OIDC_SESSION_LOA, requestedLoa);
        }

        List<AuthenticationType> allowedAuthenticationMethodsList = getAllowedAuthenticationTypes(taraScopes, requestedLoa);
        session.setAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS,
                allowedAuthenticationMethodsList
        );
    }

    private boolean isInvalidClient(OidcAuthorizeRequestValidator.InvalidRequestException e) {
        return e.getInvalidParameter() == OidcAuthorizeRequestParameter.REDIRECT_URI || e.getInvalidParameter() == OidcAuthorizeRequestParameter.CLIENT_ID;
    }

    @SneakyThrows
    private String getRedirectUrlToRelyingParty(HttpServletRequest request, OidcAuthorizeRequestValidator.InvalidRequestException e) {
        String redirectUri = request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey());
        Assert.notNull(redirectUri, "redirect_uri is required");

        String state = request.getParameter(OidcAuthorizeRequestParameter.STATE.getParameterKey());

        return RedirectUrlUtil.createRedirectUrl(redirectUri, e.getErrorCode(), e.getErrorDescription(), state);
    }

    private List<AuthenticationType> getAllowedAuthenticationTypes(List<TaraScope> taraScopes, LevelOfAssurance requestedLoa) {
        List<AuthenticationType> requestedAuthMethods = getRequestedAuthenticationMethodList(taraScopes);
        List<AuthenticationType> allowedAuthenticationMethodsList = requestedAuthMethods.stream()
                .filter(this::isAuthenticationMethodEnabled)
                .filter(autMethod -> isAuthenticationMethodAllowedByRequestedLoa(requestedLoa, autMethod))
                .collect(Collectors.toList());

        if (isEmpty(allowedAuthenticationMethodsList))
            throw new OidcAuthorizeRequestValidator.InvalidRequestException(OidcAuthorizeRequestParameter.ACR_VALUES, "invalid_request",
                    "No authentication methods match the requested level of assurance. Please check your authorization request");
        log.debug("List of authentication methods to display on login page: {}", allowedAuthenticationMethodsList);
        return allowedAuthenticationMethodsList;
    }

    private List<TaraScope> getTaraScopes(HttpSession session, String[] scopeElements) {
        List<TaraScope> scopes = parseScopes(scopeElements);
        session.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, scopes);
        log.debug("Requested scopes: {}", scopes);
        return scopes;
    }

    private LevelOfAssurance getLevelOfAssurance(HttpServletRequest request) {
        final String acrValues = request.getParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey());
        if (acrValues != null) {
            return LevelOfAssurance.findByAcrName(acrValues);
        } else {
            return null;
        }
    }

    private List<AuthenticationType> getRequestedAuthenticationMethodList(List<TaraScope> scopes) {
        if (scopes.contains(TaraScope.EIDASONLY))
            return Arrays.asList(eIDAS); // eidasonly must override all other auth methods

        List<AuthenticationType> clientRequestedAuthMethods = Arrays.stream(AuthenticationType.values())
                .filter(e -> scopes.contains(e.getScope())).collect(Collectors.toList());

        if (isEmpty(clientRequestedAuthMethods)) {
            return  taraProperties.getDefaultAuthenticationMethods();
        } else {
            return clientRequestedAuthMethods;
        }
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
        int lastIndexOf = scopeElement.lastIndexOf(':');
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

    private boolean isAuthenticationMethodAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType autMethod) {
        // Allow eIDAS authentication method since LoA is determined by the IDP of the respective country
        if (autMethod == eIDAS)
            return true;

        // Allow if LoA was not requested in the first place or no level of assurance has been configured
        if (requestedLoa == null || taraProperties.getAuthenticationMethodsLoaMap() == null)
            return true;

        return isAllowedByRequestedLoa(requestedLoa, autMethod);
    }

    private boolean isAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType authenticationMethod) {
        // Allow if LoA was not configured
        if (taraProperties.getAuthenticationMethodsLoaMap() != null
                && !taraProperties.getAuthenticationMethodsLoaMap().containsKey(authenticationMethod))
            return true;

        boolean isAllowed = taraProperties.getAuthenticationMethodsLoaMap().get(authenticationMethod).ordinal() >= requestedLoa.ordinal();

        if (isAllowed) {
            log.warn("Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {}, requested level of assurance: {}", authenticationMethod, requestedLoa );
        }

        return isAllowed;
    }

    private boolean isAuthenticationMethodEnabled(AuthenticationType method) {
        return taraProperties.isPropertyEnabled(method.getPropertyName() + ".enabled");
    }

    @Override
    public void destroy() {
        log.debug("Destroy filter: {}", OidcAuthorizeRequestValidationServletFilter.class.getName());
    }

}
