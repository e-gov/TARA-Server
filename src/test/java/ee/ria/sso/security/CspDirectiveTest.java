package ee.ria.sso.security;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CspDirectiveTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void validateValueShouldSucceedWhenNeededValueProvided() {
        Assert.assertEquals(CspDirective.Value.NEEDED, CspDirective.DEFAULT_SRC.getValue());
        CspDirective.DEFAULT_SRC.validateValue("source list");
    }

    @Test
    public void validateValueShouldFailWhenNeededValueIsIllegal() {
        Assert.assertEquals(CspDirective.Value.NEEDED, CspDirective.DEFAULT_SRC.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "A CSP directive value must not contain ';'"
        ));

        CspDirective.DEFAULT_SRC.validateValue("source; list");
    }

    @Test
    public void validateValueShouldFailWhenNeededValueIsBlank() {
        Assert.assertEquals(CspDirective.Value.NEEDED, CspDirective.DEFAULT_SRC.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must have at least one value",
                CspDirective.DEFAULT_SRC.getCspName()
        ));

        CspDirective.DEFAULT_SRC.validateValue(" ");
    }

    @Test
    public void validateValueShouldFailWhenNeededValueIsEmpty() {
        Assert.assertEquals(CspDirective.Value.NEEDED, CspDirective.DEFAULT_SRC.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must have at least one value",
                CspDirective.DEFAULT_SRC.getCspName()
        ));

        CspDirective.DEFAULT_SRC.validateValue("");
    }

    @Test
    public void validateValueShouldFailWhenNeededValueNotProvided() {
        Assert.assertEquals(CspDirective.Value.NEEDED, CspDirective.DEFAULT_SRC.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must have at least one value",
                CspDirective.DEFAULT_SRC.getCspName()
        ));

        CspDirective.DEFAULT_SRC.validateValue(null);
    }

    @Test
    public void validateValueShouldSucceedWhenOptionalValueProvided() {
        Assert.assertEquals(CspDirective.Value.OPTIONAL, CspDirective.SANDBOX.getValue());
        CspDirective.SANDBOX.validateValue("value");
    }

    @Test
    public void validateValueShouldFailWhenOptionalValueIsIllegal() {
        Assert.assertEquals(CspDirective.Value.OPTIONAL, CspDirective.SANDBOX.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "A CSP directive value must not contain ';'"
        ));

        CspDirective.SANDBOX.validateValue("value;");
    }

    @Test
    public void validateValueShouldSucceedWhenOptionalValueIsBlank() {
        Assert.assertEquals(CspDirective.Value.OPTIONAL, CspDirective.SANDBOX.getValue());
        CspDirective.SANDBOX.validateValue(" ");
    }

    @Test
    public void validateValueShouldSucceedWhenOptionalValueIsEmpty() {
        Assert.assertEquals(CspDirective.Value.OPTIONAL, CspDirective.SANDBOX.getValue());
        CspDirective.SANDBOX.validateValue("");
    }

    @Test
    public void validateValueShouldSucceedWhenOptionalValueNotProvided() {
        Assert.assertEquals(CspDirective.Value.OPTIONAL, CspDirective.SANDBOX.getValue());
        CspDirective.SANDBOX.validateValue(null);
    }

    @Test
    public void validateValueShouldFailWhenNoneValueIsProvided() {
        Assert.assertEquals(CspDirective.Value.NONE, CspDirective.BLOCK_ALL_MIXED_CONTENT.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must not have a value",
                CspDirective.BLOCK_ALL_MIXED_CONTENT.getCspName()
        ));

        CspDirective.BLOCK_ALL_MIXED_CONTENT.validateValue("value");
    }

    @Test
    public void validateValueShouldFailWhenNoneValueIsBlank() {
        Assert.assertEquals(CspDirective.Value.NONE, CspDirective.BLOCK_ALL_MIXED_CONTENT.getValue());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must not have a value",
                CspDirective.BLOCK_ALL_MIXED_CONTENT.getCspName()
        ));

        CspDirective.BLOCK_ALL_MIXED_CONTENT.validateValue(" ");
    }

    @Test
    public void validateValueShouldSucceedWhenNoneValueIsEmpty() {
        Assert.assertEquals(CspDirective.Value.NONE, CspDirective.BLOCK_ALL_MIXED_CONTENT.getValue());
        CspDirective.BLOCK_ALL_MIXED_CONTENT.validateValue("");
    }

    @Test
    public void validateValueShouldSucceedWhenNoneValueNotProvided() {
        Assert.assertEquals(CspDirective.Value.NONE, CspDirective.BLOCK_ALL_MIXED_CONTENT.getValue());
        CspDirective.BLOCK_ALL_MIXED_CONTENT.validateValue(null);
    }

}