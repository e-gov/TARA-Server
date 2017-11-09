package ee.ria.sso;

import java.util.Map;

import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import ee.ria.sso.config.TestTaraConfiguration;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {TestTaraConfiguration.class})
public abstract class AbstractTest {

    protected RequestContext getRequestContext(Map<String, String> parameters) {
        MockRequestContext context = new MockRequestContext();
        MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
        parameters.forEach((k, v) ->
            map.put(k, v)
        );
        return context;
    }

}
