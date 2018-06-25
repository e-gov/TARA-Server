package ee.ria.sso.service;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.config.TaraProperties;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.execution.Event;

import java.util.HashMap;
import java.util.Map;


public class AuthenticationServiceImplTest extends AbstractTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private TaraProperties taraProperties;

    @Test
    public void testStartLoginByMobileIDFailed() {
        expectedEx.expect(RuntimeException.class);

        Map<String, String> map = new HashMap<>();
        map.put("mobileNumber", "+37252839476");
        map.put("principalCode", "38882736672");
        Event event = this.authenticationService.startLoginByMobileID(this.getRequestContext(map));
    }
}
