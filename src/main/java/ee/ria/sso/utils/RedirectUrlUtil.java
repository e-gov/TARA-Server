package ee.ria.sso.utils;

import org.apache.commons.lang3.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RedirectUrlUtil {

    public static String createRedirectUrl(String redirectUri, String error, String errorDesc, String state) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        sb.append(redirectUri);
        sb.append(redirectUri.contains("?") ? "&" : "?");
        sb.append(String.format("error=%s", URLEncoder.encode(error, UTF_8.name())));
        sb.append(String.format("&error_description=%s", URLEncoder.encode(errorDesc, UTF_8.name())));
        if (StringUtils.isNotBlank(state)) {
            sb.append(String.format("&state=%s", URLEncoder.encode(state, UTF_8.name())));
        }

        return sb.toString();
    }
}
