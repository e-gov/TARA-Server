package ee.ria.sso.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ResponseCspHeadersEnforcementFilter implements Filter {

    private static final String CSP_HEADER_NAME = "Content-Security-Policy";
    private static final String CSP_HEADER_TEMPLATE = "default-src 'none'" +
            "%s" +
            "; base-uri 'none'" +
            "; form-action 'self'%s" +
            "; frame-ancestors 'none'" +
            "; block-all-mixed-content";

    private final List<FetchDirective> allowedSourceTypes;
    private final List<String> allowedFormActions;

    public ResponseCspHeadersEnforcementFilter(List<FetchDirective> allowedSourceTypes, List<String> allowedFormActions) {
        this.allowedSourceTypes = allowedSourceTypes.stream().filter(ft -> ft != null).collect(Collectors.toList());
        this.allowedFormActions = allowedFormActions.stream().filter(StringUtils::isNotBlank).collect(Collectors.toList());
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        String callbackUrl = getCallbackUrlFromRequest(request);

        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        response.setHeader(CSP_HEADER_NAME, getFullHeaderValue(callbackUrl));

        filterChain.doFilter(servletRequest, servletResponse);

        /*if ((callbackUrl = getCallbackUrlFromRequest(request)) != null) {
            response.setHeader(CSP_HEADER_NAME, getFullHeaderValue(callbackUrl));
        }*/
    }

    @Override
    public void destroy() {
    }

    private String getFullHeaderValue(final String callbackUrl) {
        final List<String> allowedFormActions = new ArrayList<>(this.allowedFormActions);
        if (callbackUrl != null) allowedFormActions.add(callbackUrl);

        return String.format(CSP_HEADER_TEMPLATE,
                allowedSourceTypes.stream().map(s -> String.format("; %s 'self'", s.cspName)).collect(Collectors.joining()),
                allowedFormActions.stream().map(s -> String.format(" %s", s)).collect(Collectors.joining())
        );
    }

    private String getCallbackUrlFromRequest(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);

        if (session != null) {
            Object attribute = session.getAttribute("pac4jRequestedUrl");
            if (attribute != null && attribute instanceof String)
                return getCallbackUrlFromRequestedUrl((String) attribute);
        }

        return null;
    }

    private String getCallbackUrlFromRequestedUrl(String requestedUrl) {
        try {
            UriComponents uri = UriComponentsBuilder.fromUriString(requestedUrl).build();
            return uri.getQueryParams().getFirst("redirect_uri");
        } catch (Exception e) {
            return null;
        }
    }

    @Getter
    @AllArgsConstructor
    public enum FetchDirective {
        CHILD_SRC("child-src"),
        CONNECT_SRC("connect-src"),
        DEFAULT_SRC("default-src"),
        FONT_SRC("font-src"),
        FRAME_SRC("frame-src"),
        IMG_SRC("img-src"),
        MANIFEST_SRC("manifest-src"),
        MEDIA_SRC("media-src"),
        OBJECT_SRC("object-src"),
        SCRIPT_SRC("script-src"),
        STYLE_SRC("style-src"),
        WORKER_SRC("worker-src");

        @NonNull
        final String cspName;
    }

}
