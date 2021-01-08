package org.apereo.cas.security;

import ee.ria.sso.config.TaraProperties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class ResponseHeadersEnforcementFilterTest {

    private static final String MOCK_URL = "https://mock.url";
    private static final String MOCK_URL_PATH_WITH_EXTENSION = "/assets/test-file.txt";
    private static final String DEFAULT_CACHE_CONTROL_HEADER = "public,max-age=43200"; // 12h

    @Mock
    private TaraProperties taraProperties;

    @InjectMocks
    private ResponseHeadersEnforcementFilter filter;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setUp() {
        filter = new ResponseHeadersEnforcementFilter();
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void filterShouldAddCacheControlHeaderIfIsStaticResource() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL_PATH_WITH_EXTENSION);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableCacheControl(true);
        filter.setCacheControlHeader(DEFAULT_CACHE_CONTROL_HEADER);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertTrue(response.getHeaderNames().contains(HttpHeaders.CACHE_CONTROL));
        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.PRAGMA));
        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.EXPIRES));
    }

    @Test
    public void filterShouldAddCacheControlsHeaderIfNotStaticResource() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableCacheControl(true);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertTrue(response.getHeaderNames().contains(HttpHeaders.CACHE_CONTROL));
        Assert.assertTrue(response.getHeaderNames().contains(HttpHeaders.PRAGMA));
        Assert.assertTrue(response.getHeaderNames().contains(HttpHeaders.EXPIRES));
    }

    @Test
    public void filterShouldNotAddCacheControlHeaderIfItIsDisabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL_PATH_WITH_EXTENSION);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableCacheControl(false);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.CACHE_CONTROL));
        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.PRAGMA));
        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.EXPIRES));
    }

    @Test
    public void filterShouldAddEtagHeaderIfIsStaticResource() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL_PATH_WITH_EXTENSION);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableEtag(true);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertTrue(response.getHeaderNames().contains(HttpHeaders.ETAG));
    }

    @Test
    public void filterShouldNotAddEtagHeaderIfNotStaticResource() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableEtag(true);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.ETAG));
    }

    @Test
    public void filterShouldNotAddEtagHeaderIfItIsDisabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), MOCK_URL_PATH_WITH_EXTENSION);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableEtag(false);
        filter.doFilter(request, response, new MockFilterChain());

        Assert.assertFalse(response.getHeaderNames().contains(HttpHeaders.ETAG));
    }
}
