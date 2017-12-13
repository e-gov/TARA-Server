package ee.ria.sso.service.impl;

import javax.servlet.ServletContext;

import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.mvc.servlet.MvcExternalContext;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class AbstractService {

    private final MessageSource messageSource;

    public AbstractService(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    protected SharedAttributeMap<Object> getSessionMap(RequestContext context) {
        return context.getExternalContext().getSessionMap();
    }

    protected String getMessage(String key) {
        return this.messageSource.getMessage(key, new Object[]{}, LocaleContextHolder.getLocale());
    }

    protected String getMessage(String key, String defaultMessageKey) {
        try {
            return this.messageSource.getMessage(key, new Object[]{}, LocaleContextHolder.getLocale());
        } catch (NoSuchMessageException e) {
            return this.getMessage(defaultMessageKey);
        }
    }

}
