package ee.ria.sso.service.mobileid;

import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.config.mobileid.TestMobileIDConfiguration;
import ee.ria.sso.service.AbstractAuthenticationServiceTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.webflow.execution.Event;

import java.util.HashMap;
import java.util.Map;

@ContextConfiguration(
        classes = TestMobileIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
public class MobileIDAuthenticationServiceTest extends AbstractAuthenticationServiceTest {

    @Autowired
    private MobileIDConfigurationProvider idcardConfigurationProvider;

    @Autowired
    private MobileIDAuthenticationService authenticationService;

    @Test
    public void testStartLoginByMobileIDFailed() {
        expectedEx.expect(RuntimeException.class);
        // TODO: what kind of test is this

        Map<String, String> map = new HashMap<>();
        map.put("mobileNumber", "+37252839476");
        map.put("principalCode", "38882736672");

        Event event = this.authenticationService.startLoginByMobileID(this.getRequestContext(map));
    }

}
