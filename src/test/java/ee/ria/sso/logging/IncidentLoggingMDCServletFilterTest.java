package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import org.apache.commons.codec.digest.DigestUtils;
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

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class IncidentLoggingMDCServletFilterTest {

    private static final String REQUEST_ID_REGEX = "[A-Z0-9]{16}";
    public static final String MOCK_SESSION_ID = "123456abcde";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private IncidentLoggingMDCServletFilter servletFilter;

    @Before
    public void setUp() throws Exception {
        servletFilter = new IncidentLoggingMDCServletFilter();
        servletFilter.init(Mockito.mock(FilterConfig.class));
        servletFilter.destroy();
    }

    @Test
    public void doFilterShouldFailWhenNoServletRequestProvided() throws IOException, ServletException {
        expectedEx.expect(NullPointerException.class);

        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        try {
            servletFilter.doFilter(null, servletResponse, filterChain);
        } catch (Exception e) {
            verify(filterChain, Mockito.never()).doFilter(Mockito.any(), Mockito.any());
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
    public void doFilterShouldSucceedWhenSessionAndSessionIdPresent() throws IOException, ServletException {
        ServletRequest servletRequest = createMockHttpServletRequest(new IncidentLoggingMDCServletFilter.TaraSessionIdentifier("mockId"), MOCK_SESSION_ID);

        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        new IncidentLoggingMDCServletFilter().doFilter(servletRequest, servletResponse, filterChain);

        verify(filterChain, times(1)).doFilter(servletRequest, servletResponse);
        verifyServletRequestAttributes(null, servletRequest);
        verifyMDCIsEmpty();
    }

    @Test
    public void doFilterShouldSucceedWhenRequestIdIsPresentInServletAttributes() throws IOException, ServletException {
        ServletRequest servletRequest = createMockHttpServletRequest(MOCK_SESSION_ID);
        String mockForwardedRequestId = "JSILW01Z1KM9VQXK";
        servletRequest.setAttribute(Constants.MDC_ATTRIBUTE_REQUEST_ID, mockForwardedRequestId);
        ServletResponse servletResponse = createMockHttpServletResponse();
        FilterChain filterChain = createMockFilterChain(servletRequest, servletResponse);

        servletFilter.doFilter(servletRequest, servletResponse, filterChain);

        verify(filterChain, times(1)).doFilter(servletRequest, servletResponse);
        verifyServletRequestAttributes(mockForwardedRequestId, servletRequest);
        verifyMDCIsEmpty();
    }

    private void verifyServletRequestAttributes(String forwardedId, ServletRequest servletRequest) {
        String requestId = (String)servletRequest.getAttribute(Constants.MDC_ATTRIBUTE_REQUEST_ID);
        if (forwardedId != null)
            assertEquals(forwardedId, requestId);

        assertTrue(
                String.format("Expected requestId to match \"%s\", but found \"%s\"!", REQUEST_ID_REGEX, requestId),
                requestId.matches(REQUEST_ID_REGEX));
    }

    private void verifyMDCIsEmpty() {
        assertTrue(
                "MDC was expected to be empty, but content found!",
                MDC.getCopyOfContextMap().isEmpty()
        );
    }

    private MockHttpServletRequest createMockHttpServletRequest(
            String sessionId) {
        return createMockHttpServletRequest(null, sessionId);
    }

    private MockHttpServletRequest createMockHttpServletRequest(
            IncidentLoggingMDCServletFilter.TaraSessionIdentifier taraSessionIdentifier,
            String sessionId) {
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        MockHttpSession httpSession = new MockHttpSession(new MockServletContext(), sessionId);
        if (taraSessionIdentifier != null)
            httpSession.setAttribute(IncidentLoggingMDCServletFilter.TaraSessionIdentifier.TARA_SESSION_IDENTIFIER_KEY, taraSessionIdentifier);

        mockRequest.setSession(httpSession);
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
            assertNotNull("Expected requestId, but found nothing!", actualRequestId);
            assertTrue(
                    String.format("Expected requestId to match \"%s\", but found \"%s\"!", REQUEST_ID_REGEX, actualRequestId),
                    actualRequestId.matches(REQUEST_ID_REGEX));

            String actualSessionIdHash = MDC.get("sessionId");
            if (expectedSessionId == null)
                assertNull(actualSessionIdHash);
            else
                assertEquals(expectedSessionIdHash, actualSessionIdHash);

            return null;
        }).when(filterChain).doFilter(request, response);

        return filterChain;
    }
}
