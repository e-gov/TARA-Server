package ee.ria.sso.security;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CspHeaderUtil {

    public static final String CSP_HEADER_NAME = "Content-Security-Policy";
    private static final Pattern FORM_ACTION_SEARCH_PATTERN = Pattern.compile(
            "<form[^>]*action=\"([a-z0-9._~()'!*:@,;?/#+&=-]+?)\"",
            Pattern.CASE_INSENSITIVE);

    public static void addValueToExistingDirectiveInCspHeader(HttpServletResponse response, CspDirective directive, String value) {
        final String headerValue = response.getHeader(CSP_HEADER_NAME);
        final int directiveIndex = StringUtils.indexOf(headerValue, directive.getCspName());

        if (directiveIndex >= 0) {
            final StringBuilder sb = new StringBuilder(headerValue);
            int insertIndex = directiveIndex + directive.getCspName().length();
            sb.insert(insertIndex++, ' ').insert(insertIndex, value);
            response.setHeader(CSP_HEADER_NAME, sb.toString());
        }
    }

    public static String generateSerializedHashListOfAllTags(final byte[] html, final String tag) {
        return generateSerializedListWithPattern(html,
                Pattern.compile(String.format("<%s[^>]*>(.+?)</%s>", tag, tag), Pattern.DOTALL | Pattern.CASE_INSENSITIVE),
                matchResult -> generateCspHashString(
                        Arrays.copyOfRange(html, matchResult.start(1), matchResult.end(1))
                )
        );
    }

    public static String generateSerializedFormActionsList(final byte[] html) {
        return generateSerializedListWithPattern(html, FORM_ACTION_SEARCH_PATTERN,
                matchResult -> parseUrlToString(
                        Arrays.copyOfRange(html, matchResult.start(1), matchResult.end(1))
                )
        );
    }

    private static String generateSerializedListWithPattern(final byte[] html, final Pattern pattern, final Function<MatchResult, String> resultMapper) {
        final Matcher matcher = pattern.matcher(new ByteArrayCharSequence(html));
        final StringBuilder sb = new StringBuilder();

        int start = 0;

        while (matcher.find(start)) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(resultMapper.apply(matcher.toMatchResult()));
            start = matcher.end();
        }

        return sb.toString();
    }

    private static String generateCspHashString(final byte[] input) {
        final String base64Hash = Base64.getEncoder().encodeToString(DigestUtils.sha256(input));
        return "'sha256-" + base64Hash + '\'';
    }

    private static String parseUrlToString(final byte[] input) {
        final String string = new String(input, StandardCharsets.US_ASCII);
        return StringEscapeUtils.unescapeHtml4(string);
    }

    static class ByteArrayCharSequence implements CharSequence {

        private final byte[] data;
        private final int length;
        private final int offset;

        public ByteArrayCharSequence(byte[] data) {
            this(data, 0, data.length);
        }

        public ByteArrayCharSequence(byte[] data, int offset, int length) {
            this.data = data;
            this.offset = offset;
            this.length = length;
        }

        @Override
        public int length() {
            return this.length;
        }

        @Override
        public char charAt(int index) {
            return (char) (this.data[this.offset + index] & 0xff);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new ByteArrayCharSequence(this.data, this.offset + start, end - start);
        }

    }

}
