package ee.ria.sso.service.impl;

import java.util.concurrent.Future;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.RequestContext;

import com.brsanthu.googleanalytics.EventHit;
import com.brsanthu.googleanalytics.GoogleAnalytics;
import com.brsanthu.googleanalytics.GoogleAnalyticsResponse;

import ee.ria.sso.Constants;
import ee.ria.sso.service.TrackingService;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Service
public class TrackingServiceImpl implements TrackingService {

    private final static String CATEGORY = "identification";
    private GoogleAnalytics googleAnalytics;

    @Autowired
    private Environment environment;

    @PostConstruct
    protected void init() {
        this.googleAnalytics = new GoogleAnalytics(this.environment.getProperty("tara.tracking.id"));
    }

    @Override
    public Future<GoogleAnalyticsResponse> startIDCardLogin(RequestContext context) {
        EventHit hit = new EventHit(CATEGORY, "login-idc")
            .applicationName(Constants.APPLICATION_NAME)
            .eventLabel("Logimine (ID-kaart)");
        return this.googleAnalytics.postAsync(hit);
    }

    @Override
    public Future<GoogleAnalyticsResponse> startMobileIDLogin(RequestContext context) {
        EventHit hit = new EventHit(CATEGORY, "login-mid")
            .applicationName(Constants.APPLICATION_NAME)
            .eventLabel("Logimine (Mobiil-ID)");
        return this.googleAnalytics.postAsync(hit);
    }

}
