package ee.ria.sso.service;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import org.apereo.cas.authentication.principal.AbstractWebApplicationService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class AbstractServiceTest {

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    private AbstractService abstractService;

    @Before
    public void setUp() {
        abstractService = new AbstractService(messageSource);
    }

    @Test
    public void getServiceClientIdShouldReturnServiceUrlWhenMalformedServiceUrl() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        ((MockHttpServletRequest) requestContext.getExternalContext().getNativeRequest()).addParameter("service", "invalidUrl");

        String clientId = abstractService.getServiceClientId(requestContext);
        Assert.assertEquals("invalidUrl", clientId);
    }

    @Test
    public void getServiceClientIdShouldReturnServiceUrlWhenMalformedServiceUrl2() throws UnsupportedEncodingException {
        String serviceParameter = createStringFromRangeOfValues('\0', '\u007F');
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        ((MockHttpServletRequest) requestContext.getExternalContext().getNativeRequest()).addParameter("service", serviceParameter);

        String clientId = abstractService.getServiceClientId(requestContext);
        Assert.assertEquals(URLEncoder.encode(serviceParameter, "UTF-8"), clientId);
    }

    @Test
    public void getServiceClientIdShouldSucceedWhenServiceAndClientIdProvidedInRequest() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        ((MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest()).addParameter("service", "https://some.cas.url.for.testing.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.unit.test:8451/oauth/response");

        String clientId = abstractService.getServiceClientId(requestContext);
        Assert.assertEquals("openIdDemo", clientId);
    }

    @Test
    public void getServiceClientIdShouldSucceedWhenServiceAndClientIdProvidedInFlowScope() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        requestContext.getFlowScope().put("service", new AbstractWebApplicationService("", "https://some.cas.url.for.testing.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.unit.test:8451/oauth/response", "") {});

        String clientId = abstractService.getServiceClientId(requestContext);
        Assert.assertEquals("openIdDemo", clientId);
    }

    @Test
    public void getServiceClientIdShouldReturnNullWhenClientIdNotFoundInRequestNorInFlowScope() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());

        String clientId = abstractService.getServiceClientId(requestContext);
        Assert.assertEquals(null, clientId);
    }

    private RequestContext getMockRequestContext(Map<String, String> parameters) {
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

    private String createStringFromRangeOfValues(char min, char max) {
        final int length = (max - min) + 1;
        char[] values = new char[length];

        for (int i = 0; i < length; ++i) {
            values[i] = (char) (min + i);
        }

        return new String(values);
    }

}
