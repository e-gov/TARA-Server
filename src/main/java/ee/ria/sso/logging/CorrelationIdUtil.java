package ee.ria.sso.logging;

import ee.ria.sso.Constants;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpMessage;
import org.slf4j.MDC;

public class CorrelationIdUtil {

    public static final String REQUEST_ID_HEADER = "X-Request-ID";
    public static final String CORRELATION_ID_HEADER = "X-Correlation-ID";

    public static void setCorrelationIdHeadersFromMDC(HttpMessage request) {
        setRequestHeaderFromMDC(request, REQUEST_ID_HEADER, Constants.MDC_ATTRIBUTE_REQUEST_ID);
        setRequestHeaderFromMDC(request, CORRELATION_ID_HEADER, Constants.MDC_ATTRIBUTE_SESSION_ID);
    }

    private static void setRequestHeaderFromMDC(HttpMessage request, String headerName, String mdcAttributeName) {
        final String mdcAttribute = MDC.get(mdcAttributeName);

        if (StringUtils.isNotBlank(mdcAttribute))
            request.setHeader(headerName, mdcAttribute);
    }

}
