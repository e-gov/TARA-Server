package ee.ria.sso.service.impl;

import java.util.concurrent.Future;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final Logger log = LoggerFactory.getLogger(TrackingServiceImpl.class);
    private GoogleAnalytics googleAnalytics;

    @Autowired
    private Environment environment;

    @PostConstruct
    protected void init() {
        String trackingId = this.environment.getProperty("tara.tracking.id");
        if (trackingId.matches("^UA\\-[0-9]+\\-[0-9]{1}$")) {
            this.log.debug("Google Analytics will be activated ...");
            this.googleAnalytics = new GoogleAnalytics(trackingId);
        }
    }

    @Override
    public Future<GoogleAnalyticsResponse> startIDCardLogin(RequestContext context) {
        if (this.isEnabled()) {
            EventHit hit = new EventHit(CATEGORY, "login-idc")
                .applicationName(Constants.APPLICATION_NAME)
                .eventLabel("Logimine (ID-kaart)");
            return this.googleAnalytics.postAsync(hit);
        }
        return null;
    }

    @Override
    public Future<GoogleAnalyticsResponse> startMobileIDLogin(RequestContext context) {
        if (this.isEnabled()) {
            EventHit hit = new EventHit(CATEGORY, "login-mid")
                .applicationName(Constants.APPLICATION_NAME)
                .eventLabel("Logimine (Mobiil-ID)");
            return this.googleAnalytics.postAsync(hit);
        }
        return null;
    }

    private boolean isEnabled() {
        return this.googleAnalytics != null;
    }

}
