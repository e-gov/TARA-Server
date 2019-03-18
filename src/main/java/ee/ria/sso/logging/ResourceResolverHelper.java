package ee.ria.sso.logging;

import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.code.OAuthCode;

@UtilityClass
public class ResourceResolverHelper {

    public static final String OAUTH_CODE_PREFIX = OAuthCode.PREFIX + '-';
    public static final String ACCESS_TOKEN_PREFIX = AccessToken.PREFIX + '-';


    public static String maskString(String strText, int start, int end, char maskChar) {

        if(strText == null || strText.equals(""))
            return "";

        if(start < 0)
            start = 0;

        if( end > strText.length() )
            end = strText.length();

        if(start > end)
            throw new IllegalArgumentException("End index cannot be greater than start index");

        int maskLength = end - start;

        if(maskLength == 0)
            return strText;

        String strMaskString = StringUtils.repeat(maskChar, maskLength);

        return StringUtils.overlay(strText, strMaskString, start, end);
    }
}
