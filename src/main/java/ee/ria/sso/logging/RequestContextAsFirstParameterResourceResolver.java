package ee.ria.sso.logging;

import org.apereo.cas.util.AopUtils;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;
import org.springframework.core.style.StylerUtils;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


public class RequestContextAsFirstParameterResourceResolver implements AuditResourceResolver {

    private static final String SUPPLIED_PARAMETERS = "Supplied parameters: ";

    @Override
    public String[] resolveFrom(final JoinPoint joinPoint, final Object retval) {
        return toResources(AopUtils.unWrapJoinPoint(joinPoint).getArgs());
    }

    @Override
    public String[] resolveFrom(final JoinPoint joinPoint, final Exception exception) {
        return toResources(AopUtils.unWrapJoinPoint(joinPoint).getArgs());
    }

    private static String[] toResources(final Object[] args) {
        final Object object = args[0];
        if (object instanceof RequestContext) {
            final RequestContext requestContext = RequestContext.class.cast(object);
            return new String[] {SUPPLIED_PARAMETERS + StylerUtils.style(requestContext.getExternalContext().getRequestParameterMap())};
        } else if (object instanceof HttpServletRequest) {
            return new String[] {SUPPLIED_PARAMETERS + StylerUtils.style(((HttpServletRequest)object).getParameterMap())};
        }
        return new String[] {SUPPLIED_PARAMETERS + Arrays.asList((Object[]) object)};
    }


}