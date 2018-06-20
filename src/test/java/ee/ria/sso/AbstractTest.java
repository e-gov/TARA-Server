package ee.ria.sso;

import ee.ria.sso.config.TestTaraConfiguration;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.util.Map;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */
@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {TestTaraConfiguration.class})
public abstract class AbstractTest {

    protected RequestContext getRequestContext(Map<String, String> parameters) {
        MockRequestContext context = new MockRequestContext();

        MockExternalContext mockExternalContext = new MockExternalContext();
        mockExternalContext.setNativeRequest(new MockHttpServletRequest());
        context.setExternalContext(mockExternalContext);

        MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
        parameters.forEach((k, v) ->
                map.put(k, v)
        );

        return context;
    }

}
