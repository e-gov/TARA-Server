package ee.ria.sso.utils;

import org.springframework.webflow.execution.RequestContextHolder;

public class SessionMapUtil {

    private SessionMapUtil() {}

    public static Object getSessionMapValue(String sessionConstant) {
        return RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .get(sessionConstant);
    }

    public static String getStringSessionMapValue(String sessionConstant) {
        return RequestContextHolder.getRequestContext()
                .getExternalContext()
                .getSessionMap()
                .getString(sessionConstant);
    }
}
