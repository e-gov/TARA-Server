package ee.ria.sso.service.banklink;

import ee.ria.sso.CommonConstants;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.regex.Pattern;

@RunWith(SpringJUnit4ClassRunner.class)
public class HttpSessionNonceManagerTest {

    @Before
    public void before() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void noRequestContextInGenerateNonceThrowException() {
        RequestContextHolder.setRequestAttributes(null);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("An instance of ServletRequestAttributes not found in RequestContext!");

        HttpSessionNonceManager nonceManager = new HttpSessionNonceManager(3);
        nonceManager.generateNonce();
    }

    @Test
    public void nonceHasExpired() {
        HttpSessionNonceManager nonceManager = new HttpSessionNonceManager(0);
        String nonce = nonceManager.generateNonce();

        verifyNonceGenerated(nonce);

        Assert.assertNotNull(getNonceAttributeFromSession(nonce));
        boolean isNonceValid = nonceManager.verifyNonce(nonce);
        Assert.assertEquals(false, isNonceValid);
        Assert.assertNull(getNonceAttributeFromSession(nonce));
    }

    @Test
    public void whenNonceIsGeneratedAndVerifiedSuccessfully() {
        HttpSessionNonceManager nonceManager = new HttpSessionNonceManager(60);
        String nonce = nonceManager.generateNonce();

        verifyNonceGenerated(nonce);

        // first round of verification should succeed
        boolean isNonceValid = nonceManager.verifyNonce(nonce);
        Assert.assertEquals(true, isNonceValid);
        Assert.assertNull(getNonceAttributeFromSession(nonce));

        // second round of verification should fail
        isNonceValid = nonceManager.verifyNonce(nonce);
        Assert.assertEquals("Nonce should be verifiable only once!",false, isNonceValid);
        Assert.assertNull(getNonceAttributeFromSession(nonce));
    }

    private Object getNonceAttributeFromSession(String nonce) {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest().getSession(true).getAttribute(nonce);
    }

    private void verifyNonceGenerated(String nonce) {
        Assert.assertTrue("Invalid nonce generated!",
                Pattern.matches(
                        CommonConstants.UUID_REGEX,
                        nonce
                )
        );
        Assert.assertNotNull("Nonce " + nonce + " missing in session!", getNonceAttributeFromSession(nonce));
    }
}
