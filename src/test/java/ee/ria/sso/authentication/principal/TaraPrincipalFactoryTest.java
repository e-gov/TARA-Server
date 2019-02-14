package ee.ria.sso.authentication.principal;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

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
}
