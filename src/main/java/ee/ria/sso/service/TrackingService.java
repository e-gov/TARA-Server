package ee.ria.sso.service;

import java.util.concurrent.Future;

import org.springframework.webflow.execution.RequestContext;

import com.brsanthu.googleanalytics.GoogleAnalyticsResponse;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public interface TrackingService {

    Future<GoogleAnalyticsResponse> startIDCardLogin(RequestContext context);

    Future<GoogleAnalyticsResponse> startMobileIDLogin(RequestContext context);

}
