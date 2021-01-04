/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apereo.cas.security;

import ee.ria.sso.config.TaraProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

@Slf4j
public class ResponseHeadersEnforcementFilter extends AbstractSecurityFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(ResponseHeadersEnforcementFilter.class.getName());

    private static final String INIT_PARAM_ENABLE_CACHE_CONTROL = "enableCacheControl";
    private static final String INIT_PARAM_ENABLE_ETAG = "enableEtag";
    private static final String INIT_PARAM_ENABLE_XCONTENT_OPTIONS = "enableXContentTypeOptions";
    private static final String INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY = "enableStrictTransportSecurity";

    private static final String INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS = "enableXFrameOptions";
    private static final String INIT_PARAM_STRICT_XFRAME_OPTIONS = "XFrameOptions";

    private static final String INIT_PARAM_ENABLE_XSS_PROTECTION = "enableXSSProtection";
    private static final String INIT_PARAM_XSS_PROTECTION = "XSSProtection";

    private static final String INIT_PARAM_CONTENT_SECURITY_POLICY = "contentSecurityPolicy";

    private boolean enableCacheControl;
    private boolean enableEtag;
    private String noCacheControlHeader = "no-cache, no-store, max-age=0, must-revalidate";

    private String cacheControlHeader;

    private boolean enableXContentTypeOptions;
    private String xContentTypeOptionsHeader = "nosniff";

    // allow for 6 months; value is in seconds
    private boolean enableStrictTransportSecurity;
    private String strictTransportSecurityHeader = "max-age=15768000 ; includeSubDomains";

    private boolean enableXFrameOptions;
    private String XFrameOptions = "DENY";

    private boolean enableXSSProtection;
    private String XSSProtection = "1; mode=block";

    private String contentSecurityPolicy;

    @Autowired
    private TaraProperties taraProperties;

    public void setXSSProtection(final String XSSProtection) {
        this.XSSProtection = XSSProtection;
    }

    public void setXFrameOptions(final String XFrameOptions) {
        this.XFrameOptions = XFrameOptions;
    }

    public void setEnableStrictTransportSecurity(final boolean enableStrictTransportSecurity) {
        this.enableStrictTransportSecurity = enableStrictTransportSecurity;
    }

    public void setCacheControlHeader(final String cacheControlHeader) {
        this.cacheControlHeader = cacheControlHeader;
    }

    public void setEnableEtag(final boolean enableEtag) {
        this.enableEtag = enableEtag;
    }

    public void setEnableXContentTypeOptions(final boolean enableXContentTypeOptions) {
        this.enableXContentTypeOptions = enableXContentTypeOptions;
    }

    public void setEnableXFrameOptions(final boolean enableXFrameOptions) {
        this.enableXFrameOptions = enableXFrameOptions;
    }

    public void setEnableXSSProtection(final boolean enableXSSProtection) {
        this.enableXSSProtection = enableXSSProtection;
    }

    public void setContentSecurityPolicy(final String contentSecurityPolicy) {
        this.contentSecurityPolicy = contentSecurityPolicy;
    }

    public void setEnableCacheControl(final boolean enableCacheControl) {
        this.enableCacheControl = enableCacheControl;
    }

    public ResponseHeadersEnforcementFilter() {
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);
    }

    @Override
    public void setLoggerHandlerClassName(final String loggerHandlerClassName) {
        super.setLoggerHandlerClassName(loggerHandlerClassName);
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);

        SpringBeanAutowiringSupport.processInjectionBasedOnServletContext(this, filterConfig.getServletContext());

        final Enumeration initParamNames = filterConfig.getInitParameterNames();
        throwIfUnrecognizedParamName(initParamNames);

        final String enableCacheControl = filterConfig.getInitParameter(INIT_PARAM_ENABLE_CACHE_CONTROL);
        final String enableEtag = filterConfig.getInitParameter(INIT_PARAM_ENABLE_ETAG) == null ? "true" : filterConfig.getInitParameter(INIT_PARAM_ENABLE_ETAG);
        final String enableXContentTypeOptions = filterConfig.getInitParameter(INIT_PARAM_ENABLE_XCONTENT_OPTIONS);
        final String enableStrictTransportSecurity = filterConfig.getInitParameter(INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY);
        final String enableXFrameOptions = filterConfig.getInitParameter(INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS);
        final String enableXSSProtection = filterConfig.getInitParameter(INIT_PARAM_ENABLE_XSS_PROTECTION);

        try {
            this.enableCacheControl = FilterUtils.parseStringToBooleanDefaultingToFalse(enableCacheControl);
            this.cacheControlHeader = taraProperties.getCacheControlHeader();
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_CACHE_CONTROL
                    + "] with value [" + enableCacheControl + "]", e));
        }

        try {
            this.enableEtag = FilterUtils.parseStringToBooleanDefaultingToFalse(enableEtag);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_ETAG
                    + "] with value [" + enableEtag + "]", e));
        }

        try {
            this.enableXContentTypeOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXContentTypeOptions);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_XCONTENT_OPTIONS
                    + "] with value [" + enableXContentTypeOptions + "]", e));
        }

        try {
            this.enableStrictTransportSecurity = FilterUtils.parseStringToBooleanDefaultingToFalse(enableStrictTransportSecurity);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY
                    + "] with value [" + enableStrictTransportSecurity + "]", e));
        }

        try {
            this.enableXFrameOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXFrameOptions);
            this.XFrameOptions = filterConfig.getInitParameter(INIT_PARAM_STRICT_XFRAME_OPTIONS);
            if (this.XFrameOptions == null || this.XFrameOptions.isEmpty()) {
                this.XFrameOptions = "DENY";
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS
                    + "] with value [" + enableXFrameOptions + "]", e));
        }

        try {
            this.enableXSSProtection = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXSSProtection);
            this.XSSProtection = filterConfig.getInitParameter(INIT_PARAM_XSS_PROTECTION);
            if (this.XSSProtection == null || this.XSSProtection.isEmpty()) {
                this.XSSProtection = "1; mode=block";
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_XSS_PROTECTION
                    + "] with value [" + enableXSSProtection + "]", e));
        }

        this.contentSecurityPolicy = filterConfig.getInitParameter(INIT_PARAM_CONTENT_SECURITY_POLICY);
    }

    /**
     * Examines the Filter init parameter names and throws ServletException if they contain an unrecognized
     * init parameter name.
     * <p>
     * This is a stateless static method.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param initParamNames init param names, in practice as read from the FilterConfig.
     */
    static void throwIfUnrecognizedParamName(final Enumeration initParamNames) {
        final Set<String> recognizedParameterNames = new HashSet<String>();
        recognizedParameterNames.add(INIT_PARAM_ENABLE_CACHE_CONTROL);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_ETAG);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XCONTENT_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_STRICT_XFRAME_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_CONTENT_SECURITY_POLICY);
        recognizedParameterNames.add(LOGGER_HANDLER_CLASS_NAME);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XSS_PROTECTION);
        recognizedParameterNames.add(INIT_PARAM_XSS_PROTECTION);

        while (initParamNames.hasMoreElements()) {
            final String initParamName = (String) initParamNames.nextElement();
            if (!recognizedParameterNames.contains(initParamName)) {
                FilterUtils.logException(LOGGER, new ServletException("Unrecognized init parameter [" + initParamName + "].  Failing safe.  Typo" +
                        " in the web.xml configuration? " +
                        " Misunderstanding about the configuration "
                        + RequestParameterPolicyEnforcementFilter.class.getSimpleName() + " expects?"));
            }
        }
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {
        try {
            if (servletResponse instanceof HttpServletResponse) {
                final HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

                decideInsertCacheControlHeader(httpServletResponse, httpServletRequest);
                decideInsertEtagHeader(httpServletResponse, httpServletRequest);
                decideInsertStrictTransportSecurityHeader(httpServletResponse, httpServletRequest);
                decideInsertXContentTypeOptionsHeader(httpServletResponse, httpServletRequest);
                decideInsertXFrameOptionsHeader(httpServletResponse, httpServletRequest);
                decideInsertXSSProtectionHeader(httpServletResponse, httpServletRequest);
                decideInsertContentSecurityPolicyHeader(httpServletResponse, httpServletRequest);
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException(getClass().getSimpleName()
                    + " is blocking this request. Examine the cause in this stack trace to understand why.", e));
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    protected void decideInsertContentSecurityPolicyHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (this.contentSecurityPolicy == null) {
            return;
        }
        insertContentSecurityPolicyHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertContentSecurityPolicyHeader(final HttpServletResponse httpServletResponse,
                                                     final HttpServletRequest httpServletRequest) {
        this.insertContentSecurityPolicyHeader(httpServletResponse, httpServletRequest, this.contentSecurityPolicy);
    }

    protected void insertContentSecurityPolicyHeader(final HttpServletResponse httpServletResponse,
                                                     final HttpServletRequest httpServletRequest,
                                                     final String contentSecurityPolicy) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("Content-Security-Policy", contentSecurityPolicy);
        LOGGER.fine("Adding Content-Security-Policy response header " + contentSecurityPolicy + " for " + uri);
    }

    protected void decideInsertXSSProtectionHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXSSProtection) {
            return;
        }
        insertXSSProtectionHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertXSSProtectionHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        insertXSSProtectionHeader(httpServletResponse, httpServletRequest, this.XSSProtection);
    }

    protected void insertXSSProtectionHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest,
                                             final String XSSProtection) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-XSS-Protection", XSSProtection);
        LOGGER.fine("Adding X-XSS Protection " + XSSProtection + " response headers for " + uri);
    }

    protected void decideInsertXFrameOptionsHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXFrameOptions) {
            return;
        }
        insertXFrameOptionsHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertXFrameOptionsHeader(final HttpServletResponse httpServletResponse,
                                             final HttpServletRequest httpServletRequest) {
        insertXFrameOptionsHeader(httpServletResponse, httpServletRequest, this.XFrameOptions);
    }

    protected void insertXFrameOptionsHeader(final HttpServletResponse httpServletResponse,
                                             final HttpServletRequest httpServletRequest,
                                             final String xFrameOptions) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-Frame-Options", xFrameOptions);
        LOGGER.fine("Adding X-Frame Options " + xFrameOptions + " response headers for [{}]" + uri);
    }

    protected void decideInsertXContentTypeOptionsHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXContentTypeOptions) {
            return;
        }
        insertXContentTypeOptionsHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertXContentTypeOptionsHeader(final HttpServletResponse httpServletResponse,
                                                   final HttpServletRequest httpServletRequest) {
        insertXContentTypeOptionsHeader(httpServletResponse, httpServletRequest, this.xContentTypeOptionsHeader);
    }

    protected void insertXContentTypeOptionsHeader(final HttpServletResponse httpServletResponse,
                                                   final HttpServletRequest httpServletRequest,
                                                   final String xContentTypeOptionsHeader) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-Content-Type-Options", xContentTypeOptionsHeader);
        LOGGER.fine("Adding X-Content Type response headers " + xContentTypeOptionsHeader + " for " + uri);
    }

    protected void decideInsertCacheControlHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableCacheControl) {
            return;
        }
        insertCacheControlHeader(httpServletResponse, httpServletRequest);
    }

    protected void decideInsertEtagHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableEtag) {
            return;
        }
        insertEntitytagHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertCacheControlHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        insertCacheControlHeader(httpServletResponse, httpServletRequest, this.cacheControlHeader);
    }

    protected void insertEntitytagHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        insertETagHeader(httpServletResponse, httpServletRequest);
    }

    private String generateEtag(HttpServletRequest httpServletRequest) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            String staticFilesLocation = new ClassPathResource("static").getURI().getPath();
            String filePath = new URL(httpServletRequest.getRequestURL().toString()).getPath();
            if (!FilenameUtils.getExtension(filePath).equals("")) {
                File file = new File(staticFilesLocation + filePath);
                byte[] byteArray = FileUtils.readFileToByteArray(file);
                return new DigestUtils(digest.getAlgorithm()).digestAsHex(byteArray);
            } else {
                throw new IllegalStateException("Could not get extension from file!");
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalStateException("Unable to get ETag!");
        }
    }

    private ArrayList<String> staticExtensions() {
        return new ArrayList<>(Arrays.asList("css", "js", "png", "txt", "jpg", "ico", "jpeg", "bmp", "svg", "gif", "woff", "woff2"));
    }

    protected void insertETagHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        final String url = httpServletRequest.getRequestURL().toString();
        if (staticExtensions().contains(FilenameUtils.getExtension(url))) {
            httpServletResponse.addHeader(HttpHeaders.ETAG, generateEtag(httpServletRequest));
            LOGGER.fine("Adding ETAG response header for " + url);
        }
    }

    protected void insertCacheControlHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest,
                                            final String cacheControlHeader) {
        final String url = httpServletRequest.getRequestURL().toString();
        if (!staticExtensions().contains(FilenameUtils.getExtension(url))) {
            httpServletResponse.addHeader(HttpHeaders.CACHE_CONTROL, noCacheControlHeader);
            httpServletResponse.addHeader(HttpHeaders.PRAGMA, CacheControl.noCache().getHeaderValue());
            httpServletResponse.addIntHeader(HttpHeaders.EXPIRES, 0);
            LOGGER.fine("Adding No Cache Control response headers for " + url);
        } else {
            httpServletResponse.addHeader(HttpHeaders.CACHE_CONTROL, cacheControlHeader);
            LOGGER.fine("Adding Cache Control response headers for " + url);
        }
    }

    protected void decideInsertStrictTransportSecurityHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableStrictTransportSecurity) {
            return;
        }
        insertStrictTransportSecurityHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertStrictTransportSecurityHeader(final HttpServletResponse httpServletResponse,
                                                       final HttpServletRequest httpServletRequest) {
        insertStrictTransportSecurityHeader(httpServletResponse, httpServletRequest, this.strictTransportSecurityHeader);
    }

    protected void insertStrictTransportSecurityHeader(final HttpServletResponse httpServletResponse,
                                                       final HttpServletRequest httpServletRequest,
                                                       final String strictTransportSecurityHeader) {
        if (httpServletRequest.isSecure()) {
            final String uri = httpServletRequest.getRequestURI();

            httpServletResponse.addHeader("Strict-Transport-Security", strictTransportSecurityHeader);
            LOGGER.fine("Adding HSTS response headers for " + uri);
        }
    }

    @Override
    public void destroy() {
    }
}
