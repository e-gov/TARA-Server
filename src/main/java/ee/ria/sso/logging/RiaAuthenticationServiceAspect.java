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

import com.codeborne.security.AuthenticationException;

import ee.ria.sso.authentication.TaraAuthenticationException;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Aspect
@Component
public class RiaAuthenticationServiceAspect {

    private final Logger log = LoggerFactory.getLogger(RiaAuthenticationServiceAspect.class);

    @Around("execution(org.springframework.webflow.execution.Event ee.ria.sso.service.RiaAuthenticationService.*(..))")
    public Event log(ProceedingJoinPoint point) throws Throwable {
        this.log.info("Calling <RiaAuthenticationService.{}> ...", point.getSignature().getName());
        this.logArguments(point.getArgs());
        Event event;
        try {
            event = (Event) point.proceed();
        } catch (Exception e) {
            if (this.log.isDebugEnabled()) {
                this.log.error("Authentication error have been occurred", e);
            } else {
                this.log.error("Authentication error have been occurred (enable debug level for stacktrace): {}", e.getMessage());
            }
            if (e instanceof TaraAuthenticationException) {
                throw new TaraAuthenticationException("Authentication error", new AuthenticationException(((TaraAuthenticationException) e).getCode()));
            }
            throw new TaraAuthenticationException("Authentication error");
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

}
