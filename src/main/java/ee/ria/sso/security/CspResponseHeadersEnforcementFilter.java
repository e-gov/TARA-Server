package ee.ria.sso.security;

import ee.ria.sso.Constants;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CspResponseHeadersEnforcementFilter implements Filter {

    private final String cspHeaderValue;
    private final boolean isFormActionLimited;

    public CspResponseHeadersEnforcementFilter(final Map<CspDirective, String> directives) {
        final List<String> directivesList = getDirectivesAsStringsList(directives);
        this.isFormActionLimited = directives.containsKey(CspDirective.FORM_ACTION);

        if (!directivesList.isEmpty()) {
            if (this.isFormActionLimited) moveFormActionDirectiveToLast(directivesList);
            this.cspHeaderValue = directivesList.stream().collect(Collectors.joining("; "));
        } else {
            this.cspHeaderValue = null;
        }
    }

    private List<String> getDirectivesAsStringsList(final Map<CspDirective, String> directivesMap) {
        final List<String> directivesList = new ArrayList<>();

        directivesMap.forEach((k, v) -> {
            k.validateValue(v);

            String directive = k.getCspName();
            if (StringUtils.isNotBlank(v)) {
                directive = directive + ' ' + v;
            }

            directivesList.add(directive);
        });

        return directivesList;
    }

    private void moveFormActionDirectiveToLast(List<String> directivesList) {
        final String directiveString = directivesList.stream()
                .filter(s -> s.startsWith(CspDirective.FORM_ACTION.getCspName()))
                .findFirst().get();

        directivesList.remove(directiveString);
        directivesList.add(directiveString);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        if (this.cspHeaderValue != null) {
            final HttpServletRequest request = (HttpServletRequest) servletRequest;
            final HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setHeader(CspHeaderUtil.CSP_HEADER_NAME, getFullHeaderValue(request));
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
    }

    private String getFullHeaderValue(final HttpServletRequest request) {
        if (this.isFormActionLimited) {
            final HttpSession session = request.getSession(false);

            if (session != null) {
                final Object sessionAttribute = session.getAttribute(
                        Constants.TARA_OIDC_SESSION_REDIRECT_URI
                );
                if (sessionAttribute != null && sessionAttribute instanceof String)
                    return this.cspHeaderValue + ' ' + sessionAttribute;
            }
        }

        return this.cspHeaderValue;
    }

}
