package ee.ria.sso.endpoints;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import ee.ria.sso.Constants;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.utils.X509Utils;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Controller
public class IDCardController {

    private static final String HEADER_SSL_CLIENT_CERT = "XCLIENTCERTIFICATE";
    private final Logger log = LoggerFactory.getLogger(IDCardController.class);
    private final StatisticsHandler statistics;

    public IDCardController(StatisticsHandler statistics) {
        this.statistics = statistics;
    }

    @GetMapping(path = {"/idcard"})
    public ModelAndView handleRequest(HttpServletRequest request) throws Exception {
        try {
            /*this.statistics.collect(LocalDateTime.now(), request,
                StatisticsAuthenticationType.ID_CARD, StatisticsOperation.START_AUTH);*/
            String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
            Assert.hasLength(encodedCertificate, "Unable to find certificate from request");
            request.getSession().setAttribute(Constants.CERTIFICATE_SESSION_ATTRIBUTE, X509Utils.toX509Certificate(encodedCertificate));
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("ok", true));
        } catch (Exception e) {
            /*this.statistics.collect(LocalDateTime.now(), request, StatisticsAuthenticationType.ID_CARD,
                StatisticsOperation.ERROR, e.getMessage());*/
            this.log(e);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("ok", false));
        }
    }

    /*
     * RESTRICTED METHODS
     */

    private void log(Exception e) {
        if (this.log.isDebugEnabled()) {
            this.log.error("ID-Card controller error", e);
        } else {
            this.log.error("ID-Card controller error: {}", e.getMessage());
        }
    }

}
