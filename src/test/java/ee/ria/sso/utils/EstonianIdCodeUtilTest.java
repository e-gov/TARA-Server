package ee.ria.sso.utils;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EstonianIdCodeUtilTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testValidEstonianIdCodeVerification() {
        Assert.assertTrue(
                "Failed to verify EE32307130002 as an Estonian ID code",
                EstonianIdCodeUtil.isEEPrefixedEstonianIdCode("EE32307130002")
        );
    }

    @Test
    public void testInvalidEstonianIdCodeVerification() {
        List<String> list = Arrays.asList(
                "AB32307130002",    // Not Estonian
                "EE3230713002",     // Too short
                "EE323071300002",   // Too long
                "EE02307130002",    // Invalid century/sex
                "EE72307130002",    // Invalid century/sex
                "EE32300130002",    // Invalid month
                "EE32313130002",    // Invalid month
                "EE32307000002",    // Invalid day
                "EE32307320002"     // Invalid day
        );

        for (String idCode : list) {
            Assert.assertFalse(
                    String.format("Verified %s as a valid Estonian ID code", idCode),
                    EstonianIdCodeUtil.isEEPrefixedEstonianIdCode(idCode)
            );
        }
    }

    @Test
    public void testDateOfBirthExtractionFromEstonianIdentityCodes() {
        Map<String, String> map = new HashMap<>();
        map.put("EE10001010000", "1800-01-01");
        map.put("EE20203040001", "1802-03-04");
        map.put("EE32307130002", "1923-07-13");
        map.put("EE45408240005", "1954-08-24");
        map.put("EE57511290011", "2075-11-29");
        map.put("EE69612310256", "2096-12-31");

        for (String idCode : map.keySet()) {
            Assert.assertTrue(
                    String.format("Didn't verify %s as a valid Estonian identity code", idCode),
                    EstonianIdCodeUtil.isEEPrefixedEstonianIdCode(idCode)
            );

            String expectedDateOfBirth = map.get(idCode);
            String extractedDateOfBirth = EstonianIdCodeUtil.extractDateOfBirthFromEEPrefixedEstonianIdCode(idCode);

            Assert.assertEquals(
                    String.format(
                            "Extracted date of birth (%s) doesn't match expected date of birth (%s) for identity code %s",
                            extractedDateOfBirth, expectedDateOfBirth, idCode
                    ),
                    expectedDateOfBirth, extractedDateOfBirth
            );
        }
    }

    @Test
    public void testGetEEPrefixedEstonianIdCodeWithSupportedEstonianIdentityCodeFormats() {
        final String[] identityCodePrefixes = {"", "EE", "PNOEE-"};
        final String identityCode = "69612310256";

        for (String prefix : identityCodePrefixes) {
            String prefixedIdentityCode = EstonianIdCodeUtil.getEEPrefixedEstonianIdCode(prefix + identityCode);
            Assert.assertEquals("EE" + identityCode, prefixedIdentityCode);
        }
    }

    @Test
    public void testGetEEPrefixedEstonianIdCodeWithInvalidEstonianIdentityCode() {
        final String prefixedIdentityCode = "PREFIX69612310256";

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Invalid Estonian identity code");

        EstonianIdCodeUtil.getEEPrefixedEstonianIdCode(prefixedIdentityCode);
    }

}
