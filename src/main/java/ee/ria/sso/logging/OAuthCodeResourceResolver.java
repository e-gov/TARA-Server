package ee.ria.sso.logging;

import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;

public class OAuthCodeResourceResolver implements AuditResourceResolver {

    @Override
    public String[] resolveFrom(JoinPoint target, Object returnValue) {
        OAuthCode oAuthCode = (OAuthCode) returnValue;
        String id = oAuthCode.getId();
        return new String[] {ResourceResolverHelper.maskString(id, ResourceResolverHelper.OAUTH_CODE_PREFIX.length(),
                id.length() - 10, '*')};
    }

    @Override
    public String[] resolveFrom(JoinPoint target, Exception exception) {
        final String message = exception.getMessage();
        if (message != null) {
            return new String[] {message};
        }
        return new String[] {exception.toString()};
    }
}
