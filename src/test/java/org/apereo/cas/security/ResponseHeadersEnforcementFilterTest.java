package org.apereo.cas.security;

import org.apache.commons.collections4.CollectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ResponseHeadersEnforcementFilterTest {

    ResponseHeadersEnforcementFilter filter;

    @Before
    public void setUp() {
        filter = new ResponseHeadersEnforcementFilter();
    }

    @Test
    public void doFilterShouldNotAddCacheControlHeadersWhenCacheControlIsDisabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "someRequestUri");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableCacheControl(false);
        filter.doFilter(request, response, new MockFilterChain());

        assertResponseDoesNotContainAnyCacheControlHeaders(response);
    }

    @Test
    public void doFilterShouldNotAddCacheControlHeadersForAnyContentWithSpecificExtensions() throws Exception {
        filter.setEnableCacheControl(true);

        for (String extension : new String[] {".css", ".js", ".png", ".jpg", ".ico", ".jpeg", ".bmp", ".gif", ".svg", ".woff", ".woff2"}) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET","someRequestUri" + extension);
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, new MockFilterChain());

            assertResponseDoesNotContainAnyCacheControlHeaders(response);
        }
    }

    @Test
    public void doFilterShouldAddCacheControlHeadersForAllContentWithoutSpecificExtensions() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "someRequestUri.someRandomExtension");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.setEnableCacheControl(true);
        filter.doFilter(request, response, new MockFilterChain());

        assertResponseContainsAllCacheControlHeaders(response);
    }

    private void assertResponseDoesNotContainAnyCacheControlHeaders(MockHttpServletResponse response) {
        final List<String> cacheControlHeaderNames = Arrays.asList("Cache-Control", "Pragma", "Expires");

        Assert.assertFalse(
                "Response must not contain any of " + cacheControlHeaderNames,
                CollectionUtils.containsAny(response.getHeaderNames(), cacheControlHeaderNames)
        );
    }

    private void assertResponseContainsAllCacheControlHeaders(MockHttpServletResponse response) {
        final Map<String, Object> cacheControlHeaders = new HashMap<>();

        cacheControlHeaders.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        cacheControlHeaders.put("Pragma", "no-cache");
        cacheControlHeaders.put("Expires", 0);

        cacheControlHeaders.forEach((key, value) -> {
            Assert.assertTrue("Response must contain " + key + " header", response.containsHeader(key));
            Assert.assertEquals(value, response.getHeaderValue(key));
        });
    }

}