package org.apereo.cas.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.webflow.execution.repository.BadlyFormattedFlowExecutionKeyException;
import org.springframework.webflow.execution.repository.FlowExecutionRepositoryException;

import ee.ria.sso.flow.AbstractFlowExecutionException;

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
            if (log.isDebugEnabled()) {
                log.error("Flow execution error", exception);
            } else {
                log.error("Flow execution error: {}", exception.getMessage());
            }
            ModelAndView mw = new ModelAndView(((AbstractFlowExecutionException) exception).getView(),
                ((AbstractFlowExecutionException) exception).getModel());
            mw.setStatus(((AbstractFlowExecutionException) exception).getStatus());
            return mw;
        } else {
            log.debug("Ignoring the received exception due to a type mismatch", exception);
            return null;
        }
    }

}
