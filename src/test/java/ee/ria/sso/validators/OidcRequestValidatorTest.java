package ee.ria.sso.validators;

import ee.ria.sso.CommonConstants;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.*;
import java.util.stream.Collectors;

@RunWith(SpringJUnit4ClassRunner.class)
public class OidcRequestValidatorTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    ApplicationContext applicationContext;

    @Mock
    ServicesManager servicesManager;

    @InjectMocks
    OidcRequestValidator oidcRequestValidator;

    @Before
    public void before() {
        new ApplicationContextProvider().setApplicationContext(applicationContext);
        Mockito.when(applicationContext.getBean(Mockito.eq("servicesManager"), Mockito.any(Class.class))).thenReturn(servicesManager);

        OidcRegisteredService service = new OidcRegisteredService();
        service.setClientId(CommonConstants.OIDC_CLIENT_ID);
        service.setServiceId(CommonConstants.OIDC_REDIRECT_URI + ".*");

        Collection<RegisteredService> services = new ArrayList<>();
        services.add(service);

        Mockito.when(servicesManager.getAllServices()).thenReturn(services);
    }

    @Test
    public void successWhenOnlyMandatoryParametersPresentAndValid() {
        MockHttpServletRequest request = new MockOidcRequestBuilder().addAllMandatoryParameters().build();

        oidcRequestValidator.validateAuthenticationRequestParameters(request);
    }

    @Test
    public void successWhenAllParametersPresentAndValid() {
        MockHttpServletRequest request = new MockOidcRequestBuilder()
                .addAllMandatoryParameters().build();
        oidcRequestValidator.validateAuthenticationRequestParameters(request);
    }

    @Test
    public void failWhenNoParametersProvided() {
        expectedEx.expect(OidcRequestValidator.InvalidRequestException.class);
        expectedEx.expectMessage("No value found in the request for <client_id> parameter");
        oidcRequestValidator.validateAuthenticationRequestParameters(new MockOidcRequestBuilder().build());
    }

    @Test
    public void failWhenMissingMandatoryParameter() {
        List<OidcRequestParameter> mandatoryParameters = Arrays.asList(OidcRequestParameter.values()).stream().filter(v -> v.isMandatory()).collect(Collectors.toList());
        for (OidcRequestParameter mandatoryParameter : mandatoryParameters) {
            MockHttpServletRequest request = new MockOidcRequestBuilder().addAllMandatoryParameters()
                    .removeParameter(mandatoryParameter.getParameterKey()).build();

            expectedEx.expect(OidcRequestValidator.InvalidRequestException.class);
            expectedEx.expectMessage("No value found in the request for <" + mandatoryParameter.getParameterKey() + "> parameter");
            oidcRequestValidator.validateAuthenticationRequestParameters(request);
        }
    }

    @Test
    public void failWhenParameterHasMultipleValues() {
        for (OidcRequestParameter parameter : Arrays.asList(OidcRequestParameter.values())) {
            MockHttpServletRequest request = new MockOidcRequestBuilder().addAllMandatoryParameters()
                    .removeParameter(parameter.getParameterKey())
                    .addParameter(parameter.getParameterKey(), "value1", "value2")
                    .build();

            expectedEx.expect(OidcRequestValidator.InvalidRequestException.class);
            expectedEx.expectMessage("Multiple values found in the request for <" + parameter.getParameterKey() + "> parameter");
            oidcRequestValidator.validateAuthenticationRequestParameters(request);
        }
    }

    @Test
    public void failWhenClientIdMatchingServiceNotFound() {
        MockHttpServletRequest request = new MockOidcRequestBuilder()
                .addParameter("client_id", "unknown")
                .build();

        expectedEx.expect(OidcRequestValidator.InvalidRequestException.class);
        expectedEx.expectMessage("Unauthorized client with client_id: 'unknown'. Either the client_id was never registered or it's access has been disabled.");
        oidcRequestValidator.validateAuthenticationRequestParameters(request);
    }

    @Test
    public void failWhenRedirectUriDoesNotMatchTheService() {
        MockHttpServletRequest request = new MockOidcRequestBuilder()
                .addParameter("client_id", CommonConstants.OIDC_CLIENT_ID)
                .addParameter("redirect_uri", "http://another.url")
                .build();

        expectedEx.expect(OidcRequestValidator.InvalidRequestException.class);
        expectedEx.expectMessage("redirect_uri does not match the registration! Url to match: 'http://rp.host/return_url.*', url from client: 'http://another.url'");
        oidcRequestValidator.validateAuthenticationRequestParameters(request);
    }

    public static class MockOidcRequestBuilder {

        MockHttpServletRequest httpServletRequest;

        public MockOidcRequestBuilder() {
            this.httpServletRequest = new MockHttpServletRequest();
        }

        public MockOidcRequestBuilder addAllMandatoryParameters() {
            httpServletRequest.addParameter("client_id", CommonConstants.OIDC_CLIENT_ID);
            httpServletRequest.addParameter("scope", "openid");
            httpServletRequest.addParameter("state", "1234567890abcdefgh");
            httpServletRequest.addParameter("response_type", "code");
            httpServletRequest.addParameter("redirect_uri", CommonConstants.OIDC_REDIRECT_URI);
            return this;
        }

        public MockOidcRequestBuilder addAllOptionalParameters() {
            httpServletRequest.addParameter("nonce", "0983120382109831092830128308213098");
            httpServletRequest.addParameter("acr_values", "eidas_only");
            return this;
        }

        public MockOidcRequestBuilder removeParameter(String parameterKey) {
            httpServletRequest.removeParameter(parameterKey);
            return this;
        }

        public MockOidcRequestBuilder addParameter(String parameterKey, String... values) {
            httpServletRequest.addParameter(parameterKey, values);
            return this;
        }

        public MockHttpServletRequest build() {
            return httpServletRequest;
        }
    }
}
