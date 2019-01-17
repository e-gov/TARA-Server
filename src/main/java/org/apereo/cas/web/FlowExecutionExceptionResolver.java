package org.apereo.cas.web;

import ee.ria.sso.flow.AbstractFlowExecutionException;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.webflow.execution.repository.BadlyFormattedFlowExecutionKeyException;
import org.springframework.webflow.execution.repository.FlowExecutionRepositoryException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class FlowExecutionExceptionResolver implements HandlerExceptionResolver {

    private static final Logger log = LoggerFactory.getLogger(FlowExecutionExceptionResolver.class);
    private String modelKey = "exception.message";

    public FlowExecutionExceptionResolver() {
    }

    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception exception) {
        if (exception instanceof FlowExecutionRepositoryException && !(exception instanceof BadlyFormattedFlowExecutionKeyException)) {
            String urlToRedirectTo = request.getRequestURI() + (request.getQueryString() != null ? '?' + request.getQueryString() : "");
            log.debug("Error getting flow information for URL [{}]", urlToRedirectTo, exception);
            Map<String, Object> model = new HashMap();
            model.put(this.modelKey, StringEscapeUtils.escapeHtml4(exception.getMessage()));
            return new ModelAndView(new RedirectView(urlToRedirectTo), model);
        } else if (exception instanceof AbstractFlowExecutionException) {
            if (log.isTraceEnabled()) {
                log.trace("Flow execution error", exception);
            } else {
                log.debug("Flow execution error: {}", exception.getMessage());
            }
            return ((AbstractFlowExecutionException) exception).getModelAndView();
        } else {
            log.debug("Ignoring the received exception due to a type mismatch", exception);
            return null;
        }
    }

}
