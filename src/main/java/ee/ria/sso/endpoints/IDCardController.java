package ee.ria.sso.endpoints;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import ee.ria.sso.Constants;
import ee.ria.sso.utils.X509Utils;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Slf4j
@Controller
public class IDCardController {

    public static final String HEADER_SSL_CLIENT_CERT = "XCLIENTCERTIFICATE";

    @Audit(
            action = "CLIENT_CERT_HANDLING",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    @GetMapping(path = {"/idcard"})
    public ModelAndView handleRequest(HttpServletRequest request) throws Exception {
        try {
            String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
            Assert.notNull(encodedCertificate, "Expected header '" + HEADER_SSL_CLIENT_CERT + "' could not be found in request");
            Assert.hasLength(encodedCertificate, "Unable to find certificate from request");
            X509Certificate cert = X509Utils.toX509Certificate(encodedCertificate);
            getRenewedSession(request).setAttribute(Constants.CERTIFICATE_SESSION_ATTRIBUTE, cert);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("ok", true));
        } catch (Exception e) {
            this.log(e);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("ok", false));
        }
    }

    private void log(Exception e) {
        if (this.log.isTraceEnabled()) {
            this.log.error("ID-Card controller error: {}", e.getMessage(), e);
        } else {
            this.log.error("ID-Card controller error: {}", e.getMessage());
        }
    }

    private HttpSession getRenewedSession(HttpServletRequest request) {
        final HttpSession existingSession = request.getSession(false);

        if (existingSession != null) {
            Map<String, Object> existingSessionAttributes = getSessionAttributes(existingSession);
            existingSession.invalidate();
            final HttpSession newSession = request.getSession(true);
            copyToNewSession(existingSessionAttributes, newSession);
            log.debug("ID-Card certificate stored in renewed user session");
            return newSession;
        } else {
            log.debug("ID-Card certificate stored in new user session");
            return request.getSession(true);
        }
    }

    private void copyToNewSession(Map<String, Object> oldSessionAttributes, HttpSession newSession) {
        oldSessionAttributes.forEach((key, value) -> {
            newSession.setAttribute(key, value);
        });
    }

    private LinkedHashMap<String, Object> getSessionAttributes(HttpSession oldSession) {
        LinkedHashMap<String, Object> sessionAttributeMap = new LinkedHashMap<>();
        for (Enumeration<String> attributeNames = oldSession.getAttributeNames(); attributeNames.hasMoreElements();) {
            final String attributeName = attributeNames.nextElement();
            sessionAttributeMap.put(attributeName, oldSession.getAttribute(attributeName));
        }
        return sessionAttributeMap;
    }
}
