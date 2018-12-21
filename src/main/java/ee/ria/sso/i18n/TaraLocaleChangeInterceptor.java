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
import java.util.List;
import java.util.Locale;

@Getter
@Setter
public class TaraLocaleChangeInterceptor extends LocaleChangeInterceptor {

    public static final String DEFAULT_OIDC_LOCALE_PARAM = "ui_locales";
    private static final String[] DEFAULT_ALLOWED_LOCALE_PARAM_NAMES = {DEFAULT_OIDC_LOCALE_PARAM};
    private static final List<String> ALLOWED_LOCALE_PARAM_VALUES = Arrays.asList("et", "en", "ru");

    private String[] paramNames = DEFAULT_ALLOWED_LOCALE_PARAM_NAMES;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws ServletException {

        for (String paramName : getParamNames()) {
            String newLocale = request.getParameter(paramName);
            if (newLocale != null) {

                LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
                if (localeResolver == null) {
                    throw new IllegalStateException(
                            "No LocaleResolver found: not in a DispatcherServlet request?");
                }
                try {
                    localeResolver.setLocale(request, response, parseLocaleValue(newLocale));
                    return true;
                } catch (IllegalArgumentException ex) {
                    if (isIgnoreInvalidLocale()) {
                        logger.warn("Ignoring invalid locale value [" + newLocale + "]: " + ex.getMessage());
                    } else {
                        throw ex;
                    }
                }
            }

        }

        // Proceed in any case.
        return true;
    }

    protected Locale parseLocaleValue(String locale) {
        if (ALLOWED_LOCALE_PARAM_VALUES.contains(locale)) {
            return (isLanguageTagCompliant() ? Locale.forLanguageTag(locale) : StringUtils.parseLocaleString(locale));
        } else {
            throw new IllegalArgumentException("Invalid value specified for language selection. Supported values are: " + ALLOWED_LOCALE_PARAM_VALUES);
        }
    }

}
