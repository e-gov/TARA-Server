package ee.ria.sso.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.config.TaraResourceBundleMessageSource;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class AbstractService {

    private final Logger log = LoggerFactory.getLogger(AbstractService.class);
    private final MessageSource messageSource;

    public AbstractService(TaraResourceBundleMessageSource messageSource) {
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
            this.log.warn("No message key <{}> found, defaulting to <{}> ", key, defaultMessageKey);
            return this.getMessage(defaultMessageKey);
        }
    }

}
