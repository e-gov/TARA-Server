package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.Nullable;
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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.collections4.CollectionUtils.isNotEmpty;
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

    private boolean isInvalidClient(OidcAuthorizeRequestValidator.InvalidRequestException e) {
        return e.getInvalidParameter() == OidcAuthorizeRequestParameter.REDIRECT_URI || e.getInvalidParameter() == OidcAuthorizeRequestParameter.CLIENT_ID;
    }

    @SneakyThrows
    private String getRedirectUrlToRelyingParty(HttpServletRequest request, OidcAuthorizeRequestValidator.InvalidRequestException e) {
        String redirectUri = request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey());
        Assert.notNull(redirectUri, "redirect_uri is required");

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
        LevelOfAssurance requestedLoa = getLevelOfAssurance(request);
        if (requestedLoa != null) {
            session.setAttribute(Constants.TARA_OIDC_SESSION_LOA, requestedLoa);
        }

        List<AuthenticationType> allowedAuthenticationMethodsList = getAllowedAuthenticationTypes(taraScopes, requestedLoa);
        session.setAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS,
                allowedAuthenticationMethodsList
        );
    }

    private List<AuthenticationType> getAllowedAuthenticationTypes(List<TaraScope> taraScopes, LevelOfAssurance requestedLoa) {
        List<AuthenticationType> requestedAuthMethods = getAuthenticationMethodList(taraScopes);
        List<AuthenticationType> allowedAuthenticationMethodsList = getFilteredListOfAllowedAuthenticationMethods(requestedAuthMethods, requestedLoa);
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

    @Nullable
    private LevelOfAssurance getLevelOfAssurance(HttpServletRequest request) {
        final String acrValues = request.getParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey());
        if (acrValues != null) {
            return LevelOfAssurance.findByAcrName(acrValues);
        } else {
            return null;
        }
    }

    private List<AuthenticationType> getAuthenticationMethodList(List<TaraScope> scopes) {
        if (scopes.contains(TaraScope.EIDASONLY))
            return Arrays.asList(AuthenticationType.eIDAS); // eidasonly must override all other auth methods

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

    private List<AuthenticationType> getFilteredListOfAllowedAuthenticationMethods(final List<AuthenticationType> requestedAuthMethods, LevelOfAssurance requestedLoa) {
        Assert.notNull(requestedAuthMethods, "Requested auth methods cannot be null!");

        // print warning if the loa of the requested loa of some authmethods is lower than the requested loa
        List<AuthenticationType> conflicts = requestedAuthMethods.stream()
                .filter(authMethod -> (
                                requestedLoa != null && taraProperties.getAuthenticationMethodsLoaMap().containsKey(authMethod) &&
                        taraProperties.getAuthenticationMethodsLoaMap().get(authMethod).ordinal() < requestedLoa.ordinal()))
                .collect(Collectors.toList());

        if (isNotEmpty(conflicts)) {
            log.warn("Authentication methods were ignored because their level of assurance is lower than requested. Authentication methods: {}, requested auth methods: {}, requested level of assurance: {}", conflicts.toString(), requestedAuthMethods, requestedLoa );
        }

        return requestedAuthMethods.stream()
                .filter(this::isAuthenticationMethodEnabled)
                .filter(e -> isAllowedByLoa(requestedLoa, e))
                .collect(Collectors.toList());
    }

    private boolean isAllowedByLoa(LevelOfAssurance requestedLoa, AuthenticationType authenticationMethod) {
        // Ignore if LoA was not requested in the first place
        if (requestedLoa == null)
            return true;

        // Ignore eIDAS authentication method since LoA is determined by the IDP of the respective country
        if (authenticationMethod == AuthenticationType.eIDAS)
            return true;

        return taraProperties.getAuthenticationMethodsLoaMap().containsKey(authenticationMethod)
                && taraProperties.getAuthenticationMethodsLoaMap().get(authenticationMethod).ordinal() >= requestedLoa.ordinal();
    }

    private boolean isAuthenticationMethodEnabled(AuthenticationType method) {
        return taraProperties.isPropertyEnabled(method.getPropertyName() + ".enabled");
    }

    @Override
    public void destroy() {
        log.debug("Destroy filter: {}", OidcAuthorizeRequestValidationServletFilter.class.getName());
    }

}
