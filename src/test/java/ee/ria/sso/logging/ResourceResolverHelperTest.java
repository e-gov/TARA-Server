package ee.ria.sso.logging;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ResourceResolverHelperTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void successfulMasking() {
        Assert.assertEquals("", ResourceResolverHelper.maskString("", 0, 0, '*'));
        Assert.assertEquals("", ResourceResolverHelper.maskString(null, 0, 0, '*'));
        Assert.assertEquals("******", ResourceResolverHelper.maskString("secret", Integer.MIN_VALUE, Integer.MAX_VALUE, '*'));
        Assert.assertEquals("secret", ResourceResolverHelper.maskString("secret", 3, 3, '*'));
        Assert.assertEquals("s**ret", ResourceResolverHelper.maskString("secret", 1, 3, '*'));
        Assert.assertEquals("zzzzzz", ResourceResolverHelper.maskString("secret", 0, 6, 'z'));
    }

    @Test
    public void failMaskingWhenMaskEndIdxIsLessThanStartIdx() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("End index cannot be greater than start index");
        ResourceResolverHelper.maskString("secret", 0, -1, '*');
    }
}
