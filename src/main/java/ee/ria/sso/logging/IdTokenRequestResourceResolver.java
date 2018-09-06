package ee.ria.sso.logging;

import org.apereo.cas.util.AopUtils;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

public class IdTokenRequestResourceResolver implements AuditResourceResolver {

    @Override
    public String[] resolveFrom(JoinPoint target, Object returnValue) {
        return new String[] {resolveJoinPointArguments(target)};
    }

    @Override
    public String[] resolveFrom(JoinPoint target, Exception exception) {
        return new String[] {resolveJoinPointArguments(target)};
    }

    private String resolveJoinPointArguments(JoinPoint joinPoint) {
        Object[] arguments = AopUtils.unWrapJoinPoint(joinPoint).getArgs();
        HttpServletRequest request = (HttpServletRequest) arguments[0];

        List<String> list = new ArrayList<>();
        addToListIfNonNullString(list, request.getAttribute("accessTokenTicketGrantingTicketIdentifier"));
        addToListIfNonNullString(list, request.getAttribute("generatedAndEncodedIdToken"));
        return list.toString();
    }

    private static void addToListIfNonNullString(List<String> list, Object item) {
        if (item != null && item instanceof String) {
            list.add((String) item);
        }
    }

}
