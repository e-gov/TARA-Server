package ee.ria.sso.utils;

import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

public class CountryCodeUtil {

    private static final Pattern COUNTRY_CODE_PATTERN = Pattern.compile("^[A-Z]{2,2}$");

    public static boolean isValidCountryCode(String countryCode) {
        if (StringUtils.isBlank(countryCode)) {
            return false;
        }
        return COUNTRY_CODE_PATTERN.matcher(countryCode).matches();
    }
}
