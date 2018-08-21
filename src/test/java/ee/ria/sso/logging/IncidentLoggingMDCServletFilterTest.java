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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

public class IncidentLoggingMDCServletFilterTest {

    private static final String REQUEST_ID_REGEX = "[A-Z0-9]{16}";
    public static final String MOCK_SESSION_ID = "123456abcde";

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
    public void doFilterShouldSucceedWhenSessionIdIsPresent() throws IOException, ServletException {
        ServletRequest servletRequest = createMockHttpServletRequest(MOCK_SESSION_ID);
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
        mockRequest.setSession(new MockHttpSession(new MockServletContext(), sessionId));
        return mockRequest;
    }

    private MockHttpServletResponse createMockHttpServletResponse() {
        return new MockHttpServletResponse();
    }

    private FilterChain createMockFilterChain(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doAnswer((Answer) invocation -> {

            final String expectedSessionId = ((HttpServletRequest) request).getSession(true).getId();
            final String expectedSessionIdHash = expectedSessionId == null ? null :
                    Base64.getUrlEncoder().encodeToString(DigestUtils.sha256(MOCK_SESSION_ID));

            String actualRequestId = MDC.get("requestId");
            Assert.assertNotNull("Expected requestId, but found nothing!", actualRequestId);
            Assert.assertTrue(
                    String.format("Expected requestId to match \"%s\", but found \"%s\"!", REQUEST_ID_REGEX, actualRequestId),
                    actualRequestId.matches(REQUEST_ID_REGEX));

            String actualSessionIdHash = MDC.get("sessionId");
            if (expectedSessionId == null)
                Assert.assertNull(actualSessionIdHash);
            else
                Assert.assertEquals(expectedSessionIdHash, actualSessionIdHash);

            return null;
        }).when(filterChain).doFilter(request, response);

        return filterChain;
    }
}
