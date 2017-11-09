package ee.ria.sso.service;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.execution.Event;

import ee.ria.sso.AbstractTest;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class RiaAuthenticationServiceTest extends AbstractTest {

    @Autowired
    private RiaAuthenticationService riaAuthenticationService;

    @Test(expected = RuntimeException.class)
    public void testStartLoginByMobileIDFailed() {
        Map<String, String> map = new HashMap<>();
        map.put("mobileNumber", "+37252839476");
        map.put("principalCode", "38882736672");
        Event event = this.riaAuthenticationService.startLoginByMobileID(this.getRequestContext(map));
    }

}
