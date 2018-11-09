package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
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
            addContextAttribute(Constants.MDC_ATTRIBUTE_SESSION_ID, getRequestSessionId(request));

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

    private static String getRequestSessionId(HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        return getSessionIdentifier(session).getSessionId();
    }

    private static TaraSessionIdentifier getSessionIdentifier(HttpSession session) {
        Object attribute = session.getAttribute(TaraSessionIdentifier.TARA_SESSION_IDENTIFIER_KEY);
        if (attribute != null && attribute instanceof TaraSessionIdentifier)
            return (TaraSessionIdentifier) attribute;

        String sessionId = getBase64(DigestUtils.sha256(session.getId()));
        TaraSessionIdentifier sessionIdentifier = new TaraSessionIdentifier(sessionId);
        session.setAttribute(TaraSessionIdentifier.TARA_SESSION_IDENTIFIER_KEY, sessionIdentifier);

        return sessionIdentifier;
    }

    private static String getBase64(byte[] bytes) {
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    @Getter
    @AllArgsConstructor
    public static class TaraSessionIdentifier implements Serializable {

        public static final String TARA_SESSION_IDENTIFIER_KEY = TaraSessionIdentifier.class.getName();

        @NonNull
        private final String sessionId;

    }

}
