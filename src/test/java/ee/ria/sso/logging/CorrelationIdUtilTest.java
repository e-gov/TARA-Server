package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.http.Header;
import org.apache.http.HttpMessage;
import org.apache.http.client.methods.HttpGet;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.MDC;

public class CorrelationIdUtilTest {

    private static final String MOCK_REQUEST_ID = "mockRequestId";
    private static final String MOCK_SESSION_ID = "mockSessionId";

    @Test
    public void verifyCorrelationIdHeaderNameConstants() {
        Assert.assertEquals("X-Request-ID", CorrelationIdUtil.REQUEST_ID_HEADER);
        Assert.assertEquals("X-Correlation-ID", CorrelationIdUtil.CORRELATION_ID_HEADER);
    }

    @Test
    public void setCorrelationIdHeadersFromMDCShouldCallSetHeaderWithSpecificParameters() {
        HttpMessage mockRequest = Mockito.mock(HttpMessage.class);

        try {
            setMdcCorrelationValues(MOCK_REQUEST_ID, MOCK_SESSION_ID);
            CorrelationIdUtil.setCorrelationIdHeadersFromMDC(mockRequest);
        } finally {
            MDC.clear();
        }

        Mockito.verify(mockRequest, Mockito.times(1))
                .setHeader(CorrelationIdUtil.REQUEST_ID_HEADER, MOCK_REQUEST_ID);
        Mockito.verify(mockRequest, Mockito.times(1))
                .setHeader(CorrelationIdUtil.CORRELATION_ID_HEADER, MOCK_SESSION_ID);
    }

    @Test
    public void setCorrelationIdHeadersFromMDCShouldSetSpecificHeaders() {
        HttpGet getRequest = new HttpGet();

        try {
            setMdcCorrelationValues(MOCK_REQUEST_ID, MOCK_SESSION_ID);
            CorrelationIdUtil.setCorrelationIdHeadersFromMDC(getRequest);
        } finally {
            MDC.clear();
        }

        verifyExactHeaderValue(getRequest, CorrelationIdUtil.REQUEST_ID_HEADER, MOCK_REQUEST_ID);
        verifyExactHeaderValue(getRequest, CorrelationIdUtil.CORRELATION_ID_HEADER, MOCK_SESSION_ID);
    }

    public static void setMdcCorrelationValues(String requestId, String sessionId) {
        MDC.put(Constants.MDC_ATTRIBUTE_REQUEST_ID, requestId);
        MDC.put(Constants.MDC_ATTRIBUTE_SESSION_ID, sessionId);
    }

    private static void verifyExactHeaderValue(HttpMessage request, String headerName, String headerValue) {
        final Header[] headers = request.getHeaders(headerName);

        Assert.assertTrue(headerName + " header cannot be missing", ArrayUtils.isNotEmpty(headers));
        Assert.assertEquals(headerName + " header must contain one value", 1, headers.length);
        Assert.assertEquals(headerName + " header must contain " + headerValue, headerValue, headers[0].getValue());
    }

}
