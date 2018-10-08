package ee.ria.sso.security;

import ee.ria.sso.Constants;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class CspResponseHeadersEnforcementFilterTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void constructResponseCspHeadersEnforcementFilterShouldSucceedWithNoDirectives() throws Exception {
        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(Collections.emptyMap());
        validateFilterProducesNoCspHeader(filter);
    }

    @Test
    public void constructResponseCspHeadersEnforcementFilterShouldSucceedWithValidDirective() throws Exception {
        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(
                Collections.singletonMap(CspDirective.DEFAULT_SRC, "source list")
        );
        validateFilterProducesCspHeader(filter, CspDirective.DEFAULT_SRC.getCspName() + " source list");
    }

    @Test
    public void constructResponseCspHeadersEnforcementFilterShouldSucceedWithInvalidDirective() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage(String.format(
                "CSP directive %s must not have a value",
                CspDirective.BLOCK_ALL_MIXED_CONTENT.getCspName()
        ));

        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(
                Collections.singletonMap(CspDirective.BLOCK_ALL_MIXED_CONTENT, "some value")
        );
    }

    @Test
    public void doFilterShouldShouldAddSpecifiedDirectivesToCspHeader() throws Exception {
        Map<CspDirective, String> directives = new LinkedHashMap<>();
        directives.put(CspDirective.DEFAULT_SRC, "source list");
        directives.put(CspDirective.BLOCK_ALL_MIXED_CONTENT, null);

        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(directives);
        validateFilterProducesCspHeader(filter,
                CspDirective.DEFAULT_SRC.getCspName() + " source list; " + CspDirective.BLOCK_ALL_MIXED_CONTENT.getCspName());
    }

    @Test
    public void doFilterShouldAddRedirectUriToCspHeaderIfFormActionPresent() throws Exception {
        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(
                Collections.singletonMap(CspDirective.FORM_ACTION, "action list")
        );

        validateFilterProducesCspHeader(filter,
                mockHttpServletRequest("new-form-action"),
                CspDirective.FORM_ACTION.getCspName() + " action list new-form-action"
        );
    }

    @Test
    public void doFilterShouldNotAddRedirectUriToCspHeaderIfFormActionMissing() throws Exception {
        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(
                Collections.singletonMap(CspDirective.DEFAULT_SRC, "source list")
        );

        validateFilterProducesCspHeader(filter,
                mockHttpServletRequest("new-form-action"),
                CspDirective.DEFAULT_SRC.getCspName() + " source list"
        );
    }

    @Test
    public void doFilterShouldNotAddRedirectUriToCspHeaderIfNoDirectivesPresent() throws Exception {
        CspResponseHeadersEnforcementFilter filter = new CspResponseHeadersEnforcementFilter(
                Collections.emptyMap()
        );

        validateFilterProducesCspHeader(filter,
                mockHttpServletRequest("new-form-action"),
                null
        );
    }

    private void validateFilterProducesNoCspHeader(final CspResponseHeadersEnforcementFilter filter) throws IOException, ServletException {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Assert.assertNull(response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        FilterChain filterChain = mockFilterChain(request, response);

        filter.doFilter(request, response, filterChain);
        Assert.assertNull(response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));
        Mockito.verifyZeroInteractions(request);
    }

    private void validateFilterProducesCspHeader(final CspResponseHeadersEnforcementFilter filter, final String value) throws IOException, ServletException {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        validateFilterProducesCspHeader(filter, request, value);
        Mockito.verifyZeroInteractions(request);
    }

    private void validateFilterProducesCspHeader(final CspResponseHeadersEnforcementFilter filter, final HttpServletRequest request, final String value)
            throws IOException, ServletException {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Assert.assertNull(response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));

        FilterChain filterChain = mockFilterChain(request, response);

        filter.doFilter(request, response, filterChain);
        Assert.assertEquals(value, response.getHeader(CspHeaderUtil.CSP_HEADER_NAME));
    }

    private FilterChain mockFilterChain(final ServletRequest request, final ServletResponse response) throws IOException, ServletException {
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doThrow(new IllegalArgumentException("Unexpected arguments provided to filter chain"))
                .when(filterChain).doFilter(Matchers.any(), Matchers.any());
        Mockito.doNothing().when(filterChain).doFilter(request, response);

        return filterChain;
    }

    private HttpServletRequest mockHttpServletRequest(final String... formActions) {
        MockHttpSession session = new MockHttpSession();
        for (String formAction : formActions) {
            session.setAttribute(Constants.TARA_OIDC_SESSION_REDIRECT_URI, formAction);
        }

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);

        return request;
    }

}