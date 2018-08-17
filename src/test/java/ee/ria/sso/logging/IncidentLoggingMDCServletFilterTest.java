package ee.ria.sso.logging;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

public class IncidentLoggingMDCServletFilterTest {

    private static final String REQUEST_ID_REGEX = "[A-Z0-9]{16}";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private IncidentLoggingMDCServletFilter servletFilter;

    @Before
    public void setUp() {
        servletFilter = new IncidentLoggingMDCServletFilter();
    }

    @Test
    public void doFilterShouldFailWhenNoServletRequestProvided() throws IOException, ServletException {
        expectedEx.expect(NullPointerException.class);

        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        try {
            servletFilter.doFilter(null, servletResponse, filterChain);
        } catch (Exception e) {
            Mockito.verify(filterChain, Mockito.never()).doFilter(Mockito.any(), Mockito.any());
            verifyMDCIsEmpty();

            throw e;
        }
    }

    @Test
    public void doFilterShouldFailWhenNoFilterChainProvided() throws IOException, ServletException {
        expectedEx.expect(NullPointerException.class);

        ServletRequest servletRequest = createMockHttpServletRequest(null);
        ServletResponse servletResponse = createMockHttpServletResponse();

        try {
            servletFilter.doFilter(servletRequest, servletResponse, null);
        } catch (Exception e) {
            verifyMDCIsEmpty();

            throw e;
        }
    }

    @Test
    public void doFilterShouldSucceedWhenSessionIdIsMissing() throws IOException, ServletException {
        ServletRequest servletRequest = createMockHttpServletRequest(null);
        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = createMockFilterChain(servletRequest, servletResponse);

        servletFilter.doFilter(servletRequest, servletResponse, filterChain);
        Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
        verifyMDCIsEmpty();
    }

    @Test
    public void doFilterShouldSucceedWhenSessionIdIsPresent() throws IOException, ServletException {
        String sessionId = "sessionIdString";

        ServletRequest servletRequest = createMockHttpServletRequest(sessionId);
        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = createMockFilterChain(servletRequest, servletResponse);

        servletFilter.doFilter(servletRequest, servletResponse, filterChain);
        Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
        verifyMDCIsEmpty();
    }

    private void verifyMDCIsEmpty() {
        Assert.assertTrue(
                "MDC was expected to be empty, but content found!",
                MDC.getCopyOfContextMap().isEmpty()
        );
    }

    private MockHttpServletRequest createMockHttpServletRequest(String sessionId) {
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setRequestedSessionId(sessionId);

        return mockRequest;
    }

    private MockHttpServletResponse createMockHttpServletResponse() {
        return new MockHttpServletResponse();
    }

    private FilterChain createMockFilterChain(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        final String realSessionId = ((HttpServletRequest) request).getRequestedSessionId();
        final String sessionIdHash = realSessionId == null ? null :
                Base64.getUrlEncoder().encodeToString(DigestUtils.sha256(realSessionId));

        Mockito.doAnswer((Answer) invocation -> {
            String requestId = MDC.get("requestId");
            Assert.assertNotNull("Expected requestId, but found nothing!", requestId);
            Assert.assertTrue(
                    String.format("Expected requestId to match \"%s\", but found \"%s\"!", REQUEST_ID_REGEX, requestId),
                    requestId.matches(REQUEST_ID_REGEX));

            String sessionId = MDC.get("sessionId");
            if (realSessionId == null) Assert.assertNull(sessionId);
            else Assert.assertEquals(sessionIdHash, sessionId);

            return null;
        }).when(filterChain).doFilter(request, response);

        return filterChain;
    }
}
