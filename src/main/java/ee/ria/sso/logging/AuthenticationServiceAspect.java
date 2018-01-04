package ee.ria.sso.logging;

import org.apache.commons.lang3.ArrayUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.common.AbstractService;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Aspect
@Component
public class AuthenticationServiceAspect extends AbstractService {

    private final Logger log = LoggerFactory.getLogger(AuthenticationServiceAspect.class);

    public AuthenticationServiceAspect(TaraResourceBundleMessageSource messageSource) {
        super(messageSource);
    }

    @Around("execution(org.springframework.webflow.execution.Event ee.ria.sso.service.AuthenticationService.*(..))")
    public Event log(ProceedingJoinPoint point) throws Throwable {
        this.log.info("Calling <RiaAuthenticationService.{}> ...", point.getSignature().getName());
        this.logArguments(point.getArgs());
        Event event;
        try {
            event = (Event) point.proceed();
        } catch (Exception e) {
            this.logException(e);
            if (e instanceof TaraAuthenticationException) {
                throw e;
            } else {
                throw new TaraAuthenticationException(this.getMessage("message.auth.error"), e);
            }
        }
        this.log.info("Event of <{}> has been triggered", event.getId());
        return event;
    }

    /*
     * RESTRICTED METHODS
     */

    private void logArguments(Object... arguments) {
        if (ArrayUtils.isNotEmpty(arguments)) {
            if (arguments[0] != null) {
                RequestContext context = (RequestContext) arguments[0];
                this.log.info("Request: {}", context.getExternalContext().getRequestParameterMap());
            }
        }
    }

    private void logException(Exception exception) {
        if (exception != null) {
            if (this.log.isDebugEnabled()) {
                this.log.error("Authentication error have been occurred", exception);
            } else {
                this.log.error("Authentication error have been occurred (enable debug level for stacktrace): {}",
                    exception.getMessage());
            }
        }
    }

}
