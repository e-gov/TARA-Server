package org.apereo.cas.oidc.token;

import ee.ria.sso.AbstractTest;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OidcIdTokenGeneratorServiceTest extends AbstractTest {

    @Test
    public void testValidEstonianIdCodeVerification() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method verificationMethod = service.getClass().getDeclaredMethod("isEstonianIdCode", String.class);
        verificationMethod.setAccessible(true);

        Assert.assertTrue(
                "Failed to verify EE32307130002 as an Estonian ID code",
                (Boolean) verificationMethod.invoke(service, "EE32307130002")
        );
    }

    @Test
    public void testInvalidEstonianIdCodeVerification() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method verificationMethod = service.getClass().getDeclaredMethod("isEstonianIdCode", String.class);
        verificationMethod.setAccessible(true);

        List<String> list = Arrays.asList(
                "AB32307130002",    // Not Estonian
                "EE3230713002",     // Too short
                "EE323071300002"    // Too long
        );

        for (String idCode : list) {
            Assert.assertFalse(
                    String.format("Verified %s as a valid Estonian ID code", idCode),
                    (Boolean) verificationMethod.invoke(service, idCode)
            );
        }
    }

    @Test
    public void testDateOfBirthExtractionFromValidIdentityCodes() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method verificationMethod = service.getClass().getDeclaredMethod("isEstonianIdCode", String.class);
        verificationMethod.setAccessible(true);

        Method extractionMethod = service.getClass().getDeclaredMethod("tryToExtractDateOfBirth", String.class);
        extractionMethod.setAccessible(true);

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
                    (Boolean) verificationMethod.invoke(service, idCode)
            );

            String expectedDateOfBirth = map.get(idCode);
            String extractedDateOfBirth = (String) extractionMethod.invoke(service, idCode);

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
    public void testDateOfBirthExtractionFromInvalidIdentityCodes() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method extractionMethod = service.getClass().getDeclaredMethod("tryToExtractDateOfBirth", String.class);
        extractionMethod.setAccessible(true);

        List<String> list = Arrays.asList(
                "EE02307130002",    // Invalid century/sex
                "EE72307130002",    // Invalid century/sex
                "EE32300130002",    // Invalid month
                "EE32313130002",    // Invalid month
                "EE32307000002",    // Invalid day
                "EE32307320002"     // Invalid day
        );

        for (String idCode : list) {
            String extractedDateOfBirth = (String) extractionMethod.invoke(service, idCode);

            Assert.assertNull(
                    String.format(
                            "Date of birth (%s) extraction succeeded from an invalid identity code %s",
                            extractedDateOfBirth, idCode
                    ),
                    extractedDateOfBirth
            );
        }
    }

}
