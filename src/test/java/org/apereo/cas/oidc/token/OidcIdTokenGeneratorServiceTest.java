package org.apereo.cas.oidc.token;

import ee.ria.sso.AbstractTest;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OidcIdTokenGeneratorServiceTest extends AbstractTest {

    @Test
    public void testDateOfBirthExtractionFromValidIdentityCodes() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method method = service.getClass().getDeclaredMethod("tryToExtractDateOfBirth", String.class);
        method.setAccessible(true);

        Map<String, String> map = new HashMap<>();
        map.put("EE10001010000", "1800-01-01");
        map.put("EE20203040001", "1802-03-04");
        map.put("EE32307130002", "1923-07-13");
        map.put("EE45408240005", "1954-08-24");
        map.put("EE57511290011", "2075-11-29");
        map.put("EE69612310256", "2096-12-31");

        for (String idCode : map.keySet()) {
            String expectedDateOfBirth = map.get(idCode);
            String extractedDateOfBirth = (String) method.invoke(service, idCode);

            if (!expectedDateOfBirth.equals(extractedDateOfBirth)) throw new RuntimeException(
                    String.format("Extracted date of birth (%s) doesn't match expected date of birth (%s) for identity code %s",
                        extractedDateOfBirth, expectedDateOfBirth, idCode)
            );
        }
    }

    @Test
    public void testDateOfBirthExtractionFromInvalidIdentityCodes() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OidcIdTokenGeneratorService service = new OidcIdTokenGeneratorService(null, 0, null);

        Method method = service.getClass().getDeclaredMethod("tryToExtractDateOfBirth", String.class);
        method.setAccessible(true);

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
            String extractedDateOfBirth = (String) method.invoke(service, idCode);

            if (extractedDateOfBirth != null) throw new RuntimeException(
                    String.format("Date of birth (%s) extraction succeeded from an invalid identity code %s",
                            extractedDateOfBirth, idCode)
            );
        }
    }

}
