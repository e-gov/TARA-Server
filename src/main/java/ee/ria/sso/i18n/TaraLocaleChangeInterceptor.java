package ee.ria.sso.i18n;

import lombok.Getter;
import lombok.Setter;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

@Getter
@Setter
public class TaraLocaleChangeInterceptor extends LocaleChangeInterceptor {

    public static final String DEFAULT_OIDC_LOCALE_PARAM = "ui_locales";
    public static final String LOCALE_VALUE_SEPARATOR = " ";

    public static final List<String> DEFAULT_ALLOWED_LOCALE_PARAM_NAMES = Collections.unmodifiableList(Arrays.asList(DEFAULT_OIDC_LOCALE_PARAM));
    public static final List<String> SUPPORTED_LOCALE_PARAM_VALUES = Collections.unmodifiableList(Arrays.asList("et", "en", "ru"));

    private List<String> paramNames = DEFAULT_ALLOWED_LOCALE_PARAM_NAMES;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws ServletException {

        for (String paramName : getParamNames()) {
            if (updateLocale(request, response, paramName))
                return true;
        }

        // Proceed in any case.
        return true;
    }

    private boolean updateLocale(HttpServletRequest request, HttpServletResponse response, String paramName) {
        String newLocale = request.getParameter(paramName);
        if (StringUtils.isEmpty(newLocale))
            return false;

        String[] locales = newLocale.toLowerCase().split(LOCALE_VALUE_SEPARATOR);

        for (String locale : locales) {
            try {
                if (!SUPPORTED_LOCALE_PARAM_VALUES.contains(locale))
                    throw new IllegalArgumentException("Invalid value specified for language selection. Supported values are: " + SUPPORTED_LOCALE_PARAM_VALUES);

                setLocale(request, response, locale);
                return true;
            } catch (IllegalArgumentException e) {
                if (isIgnoreInvalidLocale()) {
                    logger.warn("Ignoring invalid locale value [" + newLocale + "] for parameter [" + paramName + "]: " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }

        return false;
    }

    private void setLocale(HttpServletRequest request, HttpServletResponse response, String requestedLocale) {
        Locale locale = parseLocaleValue(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        if (localeResolver == null) {
            throw new IllegalStateException(
                    "No LocaleResolver found: not in a DispatcherServlet request?");
        }

        localeResolver.setLocale(request, response, locale);
    }
}
