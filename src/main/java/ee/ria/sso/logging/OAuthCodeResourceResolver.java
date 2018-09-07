package ee.ria.sso.logging;

import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;
import org.springframework.util.Assert;

public class OAuthCodeResourceResolver implements AuditResourceResolver {

    private static final String FULL_OAUTH_CODE_PREFIX = OAuthCode.PREFIX + '-';

    public static String maskOAuthCode(String oAuthCode) throws IllegalArgumentException {
        Assert.notNull(oAuthCode, "OAuthCode cannot be null!");

        try {
            if (!oAuthCode.startsWith(FULL_OAUTH_CODE_PREFIX))
                throw new IllegalStateException("Invalid prefix");

            if (oAuthCode.length() <= FULL_OAUTH_CODE_PREFIX.length() + 10)
                throw new IllegalStateException("Too short");

            StringBuilder sb = new StringBuilder(oAuthCode);

            final int limit = oAuthCode.length() - 10;
            for (int i = FULL_OAUTH_CODE_PREFIX.length(); i < limit; ++i) {
                sb.setCharAt(i, '*');
            }

            return sb.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException(String.format("Invalid OAuthCode \"%s\"", oAuthCode), e);
        }
    }

    @Override
    public String[] resolveFrom(JoinPoint target, Object returnValue) {
        OAuthCode oAuthCode = (OAuthCode) returnValue;
        return new String[] {maskOAuthCode(oAuthCode.getId())};
    }

    @Override
    public String[] resolveFrom(JoinPoint target, Exception exception) {
        return new String[0];
    }

}
