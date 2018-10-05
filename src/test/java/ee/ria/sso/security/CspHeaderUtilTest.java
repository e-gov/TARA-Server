package ee.ria.sso.security;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CspHeaderUtilTest {

    private static final String SINGLE_SCRIPT_HTML = "<html>\n\t<head>\n\t\t<script>%s</script>\n\t</head>\n\t<body></body>\n</html>";
    private static final String DUAL_SCRIPT_HTML = "<html>\n\t<head>\n\t\t<script>%s</script>\n\t</head>\n\t<body>\n\t\t<script>%s</script>\n\t</body>\n</html>";

    private static final String SINGLE_FORM_HTML = "<html>\n\t<body>\n\t\t<form action=\"%s\">contents</form>\n\t</body>\n</html>";
    private static final String DUAL_FORM_HTML = "<html>\n\t<body>\n\t\t<form action=\"%s\">contents</form>\n\t\t<form id=\"form1\" action=\"%s\">contents</form>\n\t</body>\n</html>";

    private static final String SINGLE_LINE_JAVASCRIPT = "function func() { return \"Some contents that this tag contains.\"; }";
    private static final String MULTILINE_JAVASCRIPT = "\nfunction func() {\n\treturn \"Some contents that this tag contains.\";\n}\n";

    @Test
    public void verifyPublicConstantsValues() {
        Assert.assertEquals("Content-Security-Policy", CspHeaderUtil.CSP_HEADER_NAME);
    }

    @Test
    public void addValueToExistingDirectiveInCspHeaderShouldAddValueWhenEmptyDirectiveExistsInHeader() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setHeader(CspHeaderUtil.CSP_HEADER_NAME, String.format(
                "someDirective someValue; %s; anotherDirective anotherValue",
                CspDirective.DEFAULT_SRC.getCspName()
        ));

        CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.DEFAULT_SRC, "addedValue");
        Assert.assertEquals(
                String.format("someDirective someValue; %s addedValue; anotherDirective anotherValue", CspDirective.DEFAULT_SRC.getCspName()),
                response.getHeader(CspHeaderUtil.CSP_HEADER_NAME)
        );
    }

    @Test
    public void addValueToExistingDirectiveInCspHeaderShouldAddValueWhenDirectiveWithValuesExistsInHeader() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setHeader(CspHeaderUtil.CSP_HEADER_NAME, String.format(
                "someDirective someValue; %s someSource anotherSource; anotherDirective anotherValue",
                CspDirective.DEFAULT_SRC.getCspName()
        ));

        CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.DEFAULT_SRC, "addedValue");
        Assert.assertEquals(
                String.format("someDirective someValue; %s addedValue someSource anotherSource; anotherDirective anotherValue", CspDirective.DEFAULT_SRC.getCspName()),
                response.getHeader(CspHeaderUtil.CSP_HEADER_NAME)
        );
    }

    @Test
    public void addValueToExistingDirectiveInCspHeaderShouldNotAlterHeaderWhenDirectiveMissingInHeader() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setHeader(CspHeaderUtil.CSP_HEADER_NAME,"someDirective someValue; anotherDirective anotherValue");

        CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.DEFAULT_SRC, "addedValue");
        Assert.assertEquals(
                "someDirective someValue; anotherDirective anotherValue",
                response.getHeader(CspHeaderUtil.CSP_HEADER_NAME)
        );
    }

    @Test
    public void addValueToExistingDirectiveInCspHeaderShouldNotAddAnythingWhenCspHeaderMissing() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Assert.assertNull(response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));

        CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.DEFAULT_SRC, "addedValue");
        Assert.assertNull(response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));
    }

    @Test
    public void generateSerializedHashListOfAllTagsShouldReturnHashOfScriptTag() {
        final String sourceString = String.format(SINGLE_SCRIPT_HTML, SINGLE_LINE_JAVASCRIPT);
        Assert.assertEquals(
                String.format("'sha256-%s'", generateBase64sha256HashString(SINGLE_LINE_JAVASCRIPT)),
                CspHeaderUtil.generateSerializedHashListOfAllTags(sourceString.getBytes(StandardCharsets.UTF_8), "script")
        );
    }

    @Test
    public void generateSerializedHashListOfAllTagsShouldReturnSerializedListOfHashesOfScriptTags() {
        final String sourceString = String.format(DUAL_SCRIPT_HTML, SINGLE_LINE_JAVASCRIPT, MULTILINE_JAVASCRIPT);
        Assert.assertEquals(
                String.format("'sha256-%s' 'sha256-%s'",
                        generateBase64sha256HashString(SINGLE_LINE_JAVASCRIPT),
                        generateBase64sha256HashString(MULTILINE_JAVASCRIPT)
                ),
                CspHeaderUtil.generateSerializedHashListOfAllTags(sourceString.getBytes(StandardCharsets.UTF_8), "script")
        );
    }

    private static String generateBase64sha256HashString(final String input) {
        return Base64.getEncoder().encodeToString(DigestUtils.sha256(input));
    }

    @Test
    public void generateSerializedFormActionsListShouldReturnFormAction() {
        final String sourceString = String.format(SINGLE_FORM_HTML, "http://some.url");
        Assert.assertEquals(
                "http://some.url",
                CspHeaderUtil.generateSerializedFormActionsList(sourceString.getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void generateSerializedFormActionsListShouldReturnSerializedListOfFormActions() {
        final String sourceString = String.format(DUAL_FORM_HTML, "http://some.url", "http://some.other.url");
        Assert.assertEquals(
                "http://some.url http://some.other.url",
                CspHeaderUtil.generateSerializedFormActionsList(sourceString.getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void generateSerializedFormActionsListShouldReturnEmptyWhenFormActionContainsUnsupportedCharacters() {
        for (char c = 0; c < 0x100; ++c) {
            if (!Character.isValidCodePoint(c))
                continue;

            final String charAsString = String.valueOf(c);
            if (charAsString.matches("[A-Za-z0-9._~()'!*:@,;?/#+&=-]"))
                continue;

            final String sourceString = String.format(SINGLE_FORM_HTML, charAsString);
            Assert.assertEquals("",
                    CspHeaderUtil.generateSerializedFormActionsList(sourceString.getBytes(StandardCharsets.UTF_8))
            );
        }
    }

}