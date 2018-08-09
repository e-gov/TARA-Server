package ee.ria.sso.service;

import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.util.Map;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
public abstract class AbstractAuthenticationServiceTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    protected Environment environment;

    protected RequestContext getRequestContext(Map<String, String> requestParameters) {
        MockRequestContext context = new MockRequestContext();

        MockExternalContext mockExternalContext = new MockExternalContext();
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("service",
                "https://cas.test.url.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response");
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
        context.setExternalContext(mockExternalContext);

        if (requestParameters != null) {
            MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
            requestParameters.forEach((k, v) -> map.put(k, v));
        }

        return context;
    }

}
