package org.apereo.cas.security;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class ResponseHeadersEnforcementFilter extends AbstractSecurityFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(ResponseHeadersEnforcementFilter.class.getName());
    private static final String INIT_PARAM_ENABLE_CACHE_CONTROL = "enableCacheControl";
    private static final String INIT_PARAM_ENABLE_XCONTENT_OPTIONS = "enableXContentTypeOptions";
    private static final String INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY = "enableStrictTransportSecurity";
    private static final String INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS = "enableXFrameOptions";
    private static final String INIT_PARAM_ENABLE_XSS_PROTECTION = "enableXSSProtection";
    private boolean enableCacheControl;
    private boolean enableXContentTypeOptions;
    private boolean enableStrictTransportSecurity;
    private boolean enableXFrameOptions;
    private boolean enableXSSProtection;

    public void setEnableStrictTransportSecurity(boolean enableStrictTransportSecurity) {
        this.enableStrictTransportSecurity = enableStrictTransportSecurity;
    }

    public void setEnableCacheControl(boolean enableCacheControl) {
        this.enableCacheControl = enableCacheControl;
    }

    public void setEnableXContentTypeOptions(boolean enableXContentTypeOptions) {
        this.enableXContentTypeOptions = enableXContentTypeOptions;
    }

    public void setEnableXFrameOptions(boolean enableXFrameOptions) {
        this.enableXFrameOptions = enableXFrameOptions;
    }

    public void setEnableXSSProtection(boolean enableXSSProtection) {
        this.enableXSSProtection = enableXSSProtection;
    }

    public ResponseHeadersEnforcementFilter() {
        FilterUtils.configureLogging(this.getLoggerHandlerClassName(), LOGGER);
    }

    public void setLoggerHandlerClassName(String loggerHandlerClassName) {
        super.setLoggerHandlerClassName(loggerHandlerClassName);
        FilterUtils.configureLogging(this.getLoggerHandlerClassName(), LOGGER);
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        FilterUtils.configureLogging(this.getLoggerHandlerClassName(), LOGGER);
        Enumeration initParamNames = filterConfig.getInitParameterNames();
        throwIfUnrecognizedParamName(initParamNames);
        String enableCacheControl = filterConfig.getInitParameter("enableCacheControl");
        String enableXContentTypeOptions = filterConfig.getInitParameter("enableXContentTypeOptions");
        String enableStrictTransportSecurity = filterConfig.getInitParameter("enableStrictTransportSecurity");
        String enableXFrameOptions = filterConfig.getInitParameter("enableXFrameOptions");
        String enableXSSProtection = filterConfig.getInitParameter("enableXSSProtection");

        try {
            this.enableCacheControl = FilterUtils.parseStringToBooleanDefaultingToFalse(enableCacheControl);
        } catch (Exception var13) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [enableCacheControl] with value [" + enableCacheControl + "]", var13));
        }

        try {
            this.enableXContentTypeOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXContentTypeOptions);
        } catch (Exception var12) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [enableXContentTypeOptions] with value [" + enableXContentTypeOptions + "]", var12));
        }

        try {
            this.enableStrictTransportSecurity = FilterUtils.parseStringToBooleanDefaultingToFalse(enableStrictTransportSecurity);
        } catch (Exception var11) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [enableStrictTransportSecurity] with value [" + enableStrictTransportSecurity + "]", var11));
        }

        try {
            this.enableXFrameOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXFrameOptions);
        } catch (Exception var10) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [enableXFrameOptions] with value [" + enableXFrameOptions + "]", var10));
        }

        try {
            this.enableXSSProtection = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXSSProtection);
        } catch (Exception var9) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [enableXSSProtection] with value [" + enableXSSProtection + "]", var9));
        }

    }

    static void throwIfUnrecognizedParamName(Enumeration initParamNames) throws ServletException {
        Set<String> recognizedParameterNames = new HashSet();
        recognizedParameterNames.add("enableCacheControl");
        recognizedParameterNames.add("enableXContentTypeOptions");
        recognizedParameterNames.add("enableStrictTransportSecurity");
        recognizedParameterNames.add("enableXFrameOptions");
        recognizedParameterNames.add("loggerHandlerClassName");
        recognizedParameterNames.add("enableXSSProtection");

        while (initParamNames.hasMoreElements()) {
            String initParamName = (String) initParamNames.nextElement();
            if (!recognizedParameterNames.contains(initParamName)) {
                FilterUtils.logException(LOGGER, new ServletException("Unrecognized init parameter [" + initParamName + "].  Failing safe.  Typo in the web.xml configuration?  Misunderstanding about the configuration " + RequestParameterPolicyEnforcementFilter.class.getSimpleName() + " expects?"));
            }
        }

    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        try {
            if (servletResponse instanceof HttpServletResponse) {
                HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                String uri = httpServletRequest.getRequestURI();
                if (this.enableCacheControl && !uri.endsWith(".css") && !uri.endsWith(".js") && !uri.endsWith(".png") && !uri.endsWith(".jpg") && !uri.endsWith(".ico") && !uri.endsWith(".jpeg") && !uri.endsWith(".bmp") && !uri.endsWith(".gif")) {
                    httpServletResponse.addHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
                    httpServletResponse.addHeader("Pragma", "no-cache");
                    httpServletResponse.addIntHeader("Expires", 0);
                    LOGGER.fine("Adding Cache Control response headers for " + uri);
                }
                if (this.enableStrictTransportSecurity && servletRequest.isSecure()) {
                    httpServletResponse.addHeader("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains");
                    LOGGER.fine("Adding HSTS response headers for " + uri);
                }
                if (this.enableXContentTypeOptions &&
                    this.hasNotHeaderValue(httpServletResponse, "X-Content-Type-Options", "nosniff")) {
                    httpServletResponse.addHeader("X-Content-Type-Options", "nosniff");
                    LOGGER.fine("Adding X-Content Type response headers for " + uri);
                }
                if (this.enableXFrameOptions &&
                    this.hasNotHeaderValue(httpServletResponse, "X-Frame-Options", "DENY")) {
                    httpServletResponse.addHeader("X-Frame-Options", "DENY");
                    LOGGER.fine("Adding X-Frame Options response headers for " + uri);
                }
                if (this.enableXSSProtection &&
                    this.hasNotHeaderValue(httpServletResponse, "X-XSS-Protection", "1; mode=block")) {
                    httpServletResponse.addHeader("X-XSS-Protection", "1; mode=block");
                    LOGGER.fine("Adding X-XSS Protection response headers for " + uri);
                }
            }
        } catch (Exception var7) {
            FilterUtils.logException(LOGGER, new ServletException(this.getClass().getSimpleName() + " is blocking this request. Examine the cause in this stack trace to understand why.", var7));
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    public void destroy() {
    }

    /*
     * RESTRICTED METHODS
     */

    private boolean hasNotHeaderValue(HttpServletResponse response, String header, String value) {
        String headerValue = response.getHeader(header);
        if (StringUtils.isNotBlank(headerValue)) {
            return !headerValue.contains(value);
        }
        return true;
    }

}
