package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import org.apache.commons.lang3.ArrayUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.util.AopUtils;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;
import org.springframework.core.style.StylerUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;

public class AccessTokenRequestResourceResolver implements AuditResourceResolver {

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

        String result = "Supplied parameters: " + getParameterMapAsString(request.getParameterMap());
        Object attribute = request.getAttribute(Constants.TARA_OIDC_TOKEN_REQUEST_ATTR_ID_TOKEN);

        if (attribute instanceof String) {
            result += "; id-token: " + attribute;
        }

        attribute = request.getAttribute(Constants.TARA_OIDC_TOKEN_REQUEST_ATTR_ACCESS_TOKEN_ID);
        if (attribute instanceof String) {
            result += "; access-token: " + ResourceResolverHelper.maskString((String)attribute,
                    ResourceResolverHelper.OAUTH_CODE_PREFIX.length(), ((String) attribute).length() - 10, '*'
                    );
        }

        return result;
    }

    private String getParameterMapAsString(Map<String, String[]> map) {
        String[] initialCodeParameters = map.get(OAuth20Constants.CODE);
        if (ArrayUtils.isEmpty(initialCodeParameters))
            return StylerUtils.style(map);

        int parameterCount = initialCodeParameters.length;
        String[] maskedCodeParameters = new String[parameterCount];

        for (int i = 0; i < parameterCount; ++i) {
            try {
                maskedCodeParameters[i] = ResourceResolverHelper.maskString(
                        initialCodeParameters[i],
                        ResourceResolverHelper.OAUTH_CODE_PREFIX.length(), initialCodeParameters[i].length() - 10, '*'
                );
            } catch (Exception e) {
                maskedCodeParameters[i] = initialCodeParameters[i];
            }
        }

        Map<String, String[]> maskedMap = new LinkedHashMap<>(map);
        maskedMap.put(OAuth20Constants.CODE, maskedCodeParameters);
        return StylerUtils.style(maskedMap);
    }

}
