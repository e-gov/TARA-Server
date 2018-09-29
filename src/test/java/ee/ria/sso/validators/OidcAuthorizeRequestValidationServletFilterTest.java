package ee.ria.sso.validators;

import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.servlet.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RunWith(SpringJUnit4ClassRunner.class)
public class OidcAuthorizeRequestValidationServletFilterTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private OidcRequestValidator oidcRequestValidator;

    private OidcAuthorizeRequestValidationServletFilter servletFilter;

    @Before
    public void setUp() throws Exception {
        new ApplicationContextProvider().setApplicationContext(applicationContext);
        Mockito.when(applicationContext.getBean(Mockito.eq("oidcRequestValidator"), Mockito.any(Class.class))).thenReturn(oidcRequestValidator);
        servletFilter = new OidcAuthorizeRequestValidationServletFilter();
        servletFilter.init(Mockito.mock(FilterConfig.class));
    }

    @Test
    public void doFilterShouldExecuteWhenValidationSucceeds() throws IOException, ServletException {
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servletFilter.doFilter(new MockHttpServletRequest(), servletResponse, Mockito.mock(FilterChain.class));
        Assert.assertEquals(200, servletResponse.getStatus());
    }

    @Test
    public void throwTechnicalExceptionWhenRedirectUriCannotBeDetermined() throws IOException, ServletException {
        assertExceptionThrownWhenParameterValidationFails(OidcRequestParameter.CLIENT_ID, OidcRequestParameter.REDIRECT_URI);
    }

    @Test
    public void assertRedirectWhenParameterValidationFails() throws IOException, ServletException {
        OidcRequestParameter[] parameters = getAllParametersExcept(OidcRequestParameter.CLIENT_ID, OidcRequestParameter.REDIRECT_URI);
        assertRedirectWhenParameterValidationFails(parameters);
    }

    private void assertExceptionThrownWhenParameterValidationFails(OidcRequestParameter... parameters) throws IOException, ServletException {
        for (OidcRequestParameter parameter : parameters) {
            Mockito.doThrow(new OidcRequestValidator.InvalidRequestException(parameter, "test", "test description")).when(oidcRequestValidator).validateAuthenticationRequestParameters(Mockito.any());

            expectedEx.expect(IllegalStateException.class);
            expectedEx.expectMessage("Invalid authorization request, cannot redirect");

            servletFilter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), Mockito.mock(FilterChain.class));
        }
    }

    private void assertRedirectWhenParameterValidationFails(OidcRequestParameter... parameters) throws IOException, ServletException {
        for (OidcRequestParameter parameter : parameters) {
            Mockito.doThrow(new OidcRequestValidator.InvalidRequestException(parameter, "test", "test description")).when(oidcRequestValidator).validateAuthenticationRequestParameters(Mockito.any());

            MockHttpServletResponse servletResponse = new MockHttpServletResponse();
            servletFilter.doFilter(new MockHttpServletRequest(), servletResponse, Mockito.mock(FilterChain.class));

            Assert.assertEquals(302, servletResponse.getStatus());
            Assert.assertEquals("null?error=test&error_description=test+description", servletResponse.getRedirectedUrl());
        }
    }

    private OidcRequestParameter[] getAllParametersExcept(OidcRequestParameter... parametersToBeExcluded) {
        List<OidcRequestParameter> parameters = new ArrayList<OidcRequestParameter>(Arrays.asList(OidcRequestParameter.values()));
        parameters.removeAll(Arrays.asList(parametersToBeExcluded));
        return parameters.toArray(new OidcRequestParameter[parameters.size()]);
    }

    @After
    public void tearDown() {
        servletFilter.destroy();
    }
}
