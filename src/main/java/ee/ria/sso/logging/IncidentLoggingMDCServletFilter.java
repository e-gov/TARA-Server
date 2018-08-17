package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

public class IncidentLoggingMDCServletFilter implements Filter {

    private static final char[] REQUEST_ID_CHARACTER_SET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        try {
            final HttpServletRequest request = (HttpServletRequest) servletRequest;

            addContextAttribute(Constants.MDC_ATTRIBUTE_REQUEST_ID, generateUniqueRequestId(request));
            addContextAttribute(Constants.MDC_ATTRIBUTE_SESSION_ID, generateSessionIdHash(request));

            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            MDC.clear();
        }
    }

    @Override
    public void destroy() {
    }

    private static void addContextAttribute(final String attributeName, final Object value) {
        if (value != null && StringUtils.isNotBlank(value.toString())) {
            MDC.put(attributeName, value.toString());
        }
    }

    private static String generateUniqueRequestId(HttpServletRequest request) {
        return RandomStringUtils.random(16, REQUEST_ID_CHARACTER_SET);
    }

    private static String generateSessionIdHash(HttpServletRequest request) {
        String requestedSessionId = request.getRequestedSessionId();
        if (requestedSessionId != null)
            return getBase64(DigestUtils.sha256(requestedSessionId));
        else
            return null;
    }

    private static String getBase64(byte[] bytes) {
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

}
