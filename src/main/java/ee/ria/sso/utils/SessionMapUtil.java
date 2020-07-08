package ee.ria.sso.utils;

import org.springframework.webflow.execution.RequestContextHolder;

public class SessionMapUtil {

    public static String getSessionMapValue(String sessionConstant) {
        return RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .getString(sessionConstant);
    }
}
