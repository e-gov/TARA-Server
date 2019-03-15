package ee.ria.sso.logging;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.inspektr.audit.spi.support.ReturnValueAsStringResourceResolver;
import org.aspectj.lang.JoinPoint;
import org.springframework.util.Assert;

import java.util.Map;

import static org.apache.commons.lang3.builder.ToStringStyle.NO_CLASS_NAME_STYLE;

@Slf4j
public class UserInfoAuditResourceResolver extends ReturnValueAsStringResourceResolver {

    @Override
    public String[] resolveFrom(final JoinPoint auditableTarget, final Object retval) {
        Assert.notNull(retval, "User profile data must not be null");
        final Map profileMap = Map.class.cast(retval);
        final AccessToken accessToken = AccessToken.class.cast(auditableTarget.getArgs()[0]);

        final String result = new ToStringBuilder(this, NO_CLASS_NAME_STYLE)
            .append("access_token", ResourceResolverHelper.maskString(accessToken.getId(), ResourceResolverHelper.ACCESS_TOKEN_PREFIX.length(), accessToken.getId().length() - 10, '*'))
            .append("scopes", accessToken.getScopes())
            .append("claims", profileMap)
            .toString();

        return new String[]{result};
    }
}
