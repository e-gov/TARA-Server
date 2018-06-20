package ee.ria.sso.common;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class AbstractService {

    private final TaraResourceBundleMessageSource messageSource;

    public AbstractService(TaraResourceBundleMessageSource messageSource) {
        this.messageSource = messageSource;
    }

    protected SharedAttributeMap<Object> getSessionMap(RequestContext context) {
        return context.getExternalContext().getSessionMap();
    }

    protected String getMessage(String key) {
        return messageSource.getMessage(key);
    }

    protected String getMessage(String key, String defaultMessageKey) {
        return messageSource.getMessage(key, defaultMessageKey);
    }

    protected String getMessage(String key, String defaultMessageKey, Object... parameters) {
        return messageSource.getMessage(key, defaultMessageKey, parameters);
    }

}
