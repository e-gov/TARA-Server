package ee.ria.sso.validators;

import com.stormpath.sdk.lang.Assert;
import ee.ria.sso.Constants;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.springframework.context.ApplicationContext;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
public class OidcAuthorizeRequestValidationServletFilter implements Filter {

    private OidcRequestValidator oidcRequestValidator;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        ApplicationContext ctx = ApplicationContextProvider.getApplicationContext();
        Assert.notNull(ctx, "Spring context could not be found!");
        this.oidcRequestValidator = ctx.getBean("oidcRequestValidator", OidcRequestValidator.class);
        Assert.notNull(ctx, "OidcRequestValidator could not be not be found in Spring context!");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            this.oidcRequestValidator.validateAuthenticationRequestParameters(request);
            this.saveOidcRequestParametersToSession(request);

            filterChain.doFilter(servletRequest, servletResponse);
        } catch (OidcRequestValidator.InvalidRequestException e) {
            log.error("Invalid OIDC authorization request: " + e.getMessage());
            if (isInvalidClient(e)) {
                throw new IllegalStateException("Invalid authorization request, cannot redirect", e);
            } else {
                response.sendRedirect(getRedirectUrlToRelyingParty(request, e));
            }
        }
    }

    private boolean isInvalidClient(OidcRequestValidator.InvalidRequestException e) {
        return e.getInvalidParameter() == OidcRequestParameter.REDIRECT_URI || e.getInvalidParameter() == OidcRequestParameter.CLIENT_ID;
    }

    private String getRedirectUrlToRelyingParty(HttpServletRequest request, OidcRequestValidator.InvalidRequestException e) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(request.getParameter(OidcRequestParameter.REDIRECT_URI.getParameterKey()));
            sb.append("?");
            sb.append(String.format("error=%s", URLEncoder.encode(e.getErrorCode(), StandardCharsets.UTF_8.name())));
            sb.append(String.format("&error_description=%s", URLEncoder.encode(e.getErrorDescription(), StandardCharsets.UTF_8.name())));
            String state = request.getParameter(OidcRequestParameter.STATE.getParameterKey());
            if (StringUtils.isNotBlank(state)) {
                sb.append(String.format("&state=%s", state));
            }

            return sb.toString();
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void saveOidcRequestParametersToSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);

        session.setAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID,
                request.getParameter(OidcRequestParameter.CLIENT_ID.getParameterKey())
        );
        session.setAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI,
                request.getParameter(OidcRequestParameter.REDIRECT_URI.getParameterKey())
        );
    }

    @Override
    public void destroy() {
    }

}
