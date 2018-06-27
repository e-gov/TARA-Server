package ee.ria.sso.statistics;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.authentication.AuthenticationType;

/**
 * Created by serkp on 08.12.2017.
 */

@Component
public class StatisticsHandler {

    public static final String CAS_SERVICE_ATTRIBUTE_NAME = "service";
    private final Logger log = LoggerFactory.getLogger(StatisticsHandler.class);
    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

    public void collect(LocalDateTime time, RequestContext requestContext, AuthenticationType authenticationType,
                        StatisticsOperation operationCode) {
        Assert.notNull(requestContext, "RequestContext cannot be null!");
        Assert.isTrue(!Arrays.asList(StatisticsOperation.ERROR).contains(operationCode), "Illegal operation code");
        this.collect(time, requestContext, authenticationType, operationCode, "");
    }

    public void collect(LocalDateTime time, RequestContext requestContext, AuthenticationType authenticationType,
                        StatisticsOperation operationCode, String causeOfError) {
        Assert.notNull(requestContext, "RequestContext cannot be null!");
        Optional<String> clientId = this.getClientId(requestContext);
        if (clientId.isPresent()) {
            this.log.info(String.format("%s;%s;%s;%s;%s", this.formatter.format(time), clientId.get(), authenticationType,
                operationCode, causeOfError));
        }
    }

    /*
     * RESTRICTED METHODS
     */

    private Optional<String> getClientId(RequestContext request) {
        String serviceParameter = ((HttpServletRequest)request.getExternalContext().getNativeRequest()).getParameter(CAS_SERVICE_ATTRIBUTE_NAME);
        if (StringUtils.isNotBlank(serviceParameter)) {
            return getClientIdParameterValue(serviceParameter);
        } else if (StringUtils.isNotBlank(getServiceUrlFromFlowContext(request))) {
            return getClientIdParameterValue(getServiceUrlFromFlowContext(request));
        }

        return Optional.empty();
    }

    private Optional<String> getClientIdParameterValue(String serviceParameter) {
        UriComponents serviceUri = UriComponentsBuilder.fromUriString(serviceParameter).build();
        try {
            return Optional.of(serviceUri.getQueryParams().get("client_id").get(0));
        } catch (Exception ignore) {
            return Optional.empty();
        }
    }

    private String getServiceUrlFromFlowContext(RequestContext request) {
        Object attribute = request.getFlowScope().get(CAS_SERVICE_ATTRIBUTE_NAME);
        if (attribute != null && attribute instanceof WebApplicationService) {
            return ((WebApplicationService) attribute).getOriginalUrl();
        } else {
            return null;
        }
    }
}
