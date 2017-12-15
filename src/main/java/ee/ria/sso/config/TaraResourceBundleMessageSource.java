package ee.ria.sso.config;

import javax.annotation.PostConstruct;

import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Component;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Component
public class TaraResourceBundleMessageSource extends ResourceBundleMessageSource {

    @PostConstruct
    protected void init() {
        this.setDefaultEncoding("UTF-8");
        this.setBasename("messages");
        this.setCacheSeconds(180);
        this.setFallbackToSystemLocale(false);
        this.setUseCodeAsDefaultMessage(false);
    }

}
