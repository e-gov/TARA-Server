package ee.ria.sso.oidc;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@AllArgsConstructor
public class OidcAuthorizeRequestValidationServletFilter implements Filter {

    private final OidcAuthorizeRequestValidator oidcAuthorizeRequestValidator;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
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
            sb.append(String.format("error=%s", URLEncoder.encode(e.getErrorCode(), StandardCharsets.UTF_8.name())));
            sb.append(String.format("&error_description=%s", URLEncoder.encode(e.getErrorDescription(), StandardCharsets.UTF_8.name())));
            String state = request.getParameter(OidcAuthorizeRequestParameter.STATE.getParameterKey());
            if (StringUtils.isNotBlank(state)) {
                sb.append(String.format("&state=%s", state));
            }

            return sb.toString();
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void saveOidcRequestParametersToSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);

        final List<TaraScope> scopes = getTaraOidcScopesFromRequest(request);
        session.setAttribute(Constants.TARA_OIDC_SESSION_SCOPES, scopes);

        session.setAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID,
                request.getParameter(OidcAuthorizeRequestParameter.CLIENT_ID.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI,
                request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_AUTH_METHODS,
                getListOfAllowedAuthenticationMethods(scopes)
        );

        final String acrValues = request.getParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey());
        if (acrValues != null) session.setAttribute(Constants.TARA_OIDC_SESSION_LOA,
                LevelOfAssurance.findByAcrName(acrValues));
    }

    private List<TaraScope> getTaraOidcScopesFromRequest(final HttpServletRequest request) {
        final String scope = request.getParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey());
        if (StringUtils.isBlank(scope)) return Collections.emptyList();



        return Arrays.stream(scope.split(" "))
                .map(s -> {
                        try {
                            return TaraScope.getScope(s);
                        } catch (IllegalArgumentException e) {
                            log.warn("Invalid scope value ignored!");
                            return null;
                        }
                    })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private List<AuthenticationType> getListOfAllowedAuthenticationMethods(final List<TaraScope> scopes) {
        if (scopes.contains(TaraScope.EIDASONLY)) {
            return Arrays.asList(AuthenticationType.eIDAS);
        } else if (isAuthMethodSpecificScopePresent(scopes)) {
            return Arrays.stream(AuthenticationType.values())
                    .filter(e -> scopes.contains(e.getScope()) )
                    .collect(Collectors.toList());
        } else {
            return Arrays.stream(AuthenticationType.values())
                    .filter(e -> e != AuthenticationType.Default)
                    .collect(Collectors.toList());
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
