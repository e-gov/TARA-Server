package ee.ria.sso.service.impl;

import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import com.brsanthu.googleanalytics.GoogleAnalyticsResponse;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class AbstractService {

    private final Logger log = LoggerFactory.getLogger(AbstractService.class);
    private final MessageSource messageSource;

    public AbstractService(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    protected void handleFuture(Future<GoogleAnalyticsResponse> future) {
        try {
            if (future != null) {
                GoogleAnalyticsResponse response = future.get();
                if (this.log.isDebugEnabled()) {
                    this.log.debug("Google Analytics event <{}> call received response status: <{}>", response.getPostedParmsAsMap().get("ea"), response.getStatusCode());
                }
            }
        } catch (Exception e) {
            if (this.log.isDebugEnabled()) {
                this.log.error("Google Analytics request failed", e);
            }
        }
    }

    protected String getMessage(String key) {
        return this.messageSource.getMessage(key, new Object[]{}, LocaleContextHolder.getLocale());
    }

}
