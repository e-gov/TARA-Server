package ee.ria.sso.authentication.principal;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.oidc.MockPrincipalUtils;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.skyscreamer.jsonassert.comparator.CustomComparator;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

public class TaraPrincipalFactoryTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void createPrincipalWithIdNotSupported() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Attributes are mandatory when creating principal");
        new TaraPrincipalFactory().createPrincipal("id");
    }

    @Test
    public void createPrincipalWithEmptyAttributes() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("No attributes found when creating principal");
        new TaraPrincipalFactory().createPrincipal("id", new LinkedHashMap<>());
    }

    @Test
    public void createPrincipalCreatesPrincipalWithSortedAttributeSet() {
        Map<String, Object> inputMap = new LinkedHashMap<>();
        inputMap.put("a2", "0");
        inputMap.put("A1", "1");
        inputMap.put("a1", "2");
        inputMap.put("A3", "3");

        TaraPrincipal p = (TaraPrincipal) new TaraPrincipalFactory().createPrincipal("id", inputMap);
        Assert.assertEquals(new HashSet<>(Arrays.asList("A1", "a2", "A3")), p.getAttributes().keySet());
        Assert.assertEquals("id", p.getId());
    }

    @Test
    public void createPrincipalFromTgt() {

        TaraPrincipal p = (TaraPrincipal) TaraPrincipalFactory.createPrincipal(MockPrincipalUtils.getMockUserAuthentication());
        Assert.assertEquals(MockPrincipalUtils.TARA_PRINCIPAL_ID, p.getId());
        Assert.assertEquals(MockPrincipalUtils.TARA_PRINCIPAL_ID, p.toString());

        JSONAssert.assertEquals(
                "{\n" +
                        "  \"sub\": \"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EE + "\",\n" +
                        "  \"given_name\": \"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\n" +
                        "  \"family_name\": \"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\n" +
                        "  \"phone\": \"" + MockPrincipalUtils.MOCK_PHONE_NUBMER + "\",\n" +
                        "  \"phone_verified\": true\n," +
                        "  \"date_of_birth\": \"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\",\n" +
                        "  \"amr\": [\n" +
                        "    \"" + AuthenticationType.MobileID.getAmrName() + "\"\n" +
                        "  ]\n" +
                        "}",
                OAuth20Utils.jsonify(p.getAttributes()),
                new CustomComparator(JSONCompareMode.NON_EXTENSIBLE)
        );
    }
}
