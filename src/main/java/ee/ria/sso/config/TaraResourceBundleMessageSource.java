package ee.ria.sso.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Component
public class TaraResourceBundleMessageSource extends ResourceBundleMessageSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaraResourceBundleMessageSource.class);

    @PostConstruct
    protected void init() {
        this.setDefaultEncoding("UTF-8");
        this.setBasename("messages");
        this.setCacheSeconds(180);
        this.setFallbackToSystemLocale(false);
        this.setUseCodeAsDefaultMessage(false);
    }

    public String getMessage(String key) {
        return super.getMessage(key, new Object[]{}, LocaleContextHolder.getLocale());
    }

    public String getMessage(String key, String defaultMessageKey) {
        return this.getMessage(key, defaultMessageKey, new Object[] {});
    }

    public String getMessage(String key, String defaultMessageKey, Object... parameters) {
        try {
            return super.getMessage(key, parameters, LocaleContextHolder.getLocale());
        } catch (NoSuchMessageException e) {
            LOGGER.warn("No message key <{}> found, defaulting to <{}> ", key, defaultMessageKey);
            return this.getMessage(defaultMessageKey);
        }
    }
}
