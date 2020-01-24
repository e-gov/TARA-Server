package ee.ria.sso.service;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.util.EncodingUtils;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;


@Slf4j
@RequiredArgsConstructor
public class AbstractService {

    private final StatisticsHandler statistics;

    protected SharedAttributeMap<Object> getSessionMap(RequestContext context) {
        return context.getExternalContext().getSessionMap();
    }

    protected String getServiceClientId(RequestContext context) {
        final Object attribute = context.getExternalContext().getSessionMap()
                .get(Constants.TARA_OIDC_SESSION_CLIENT_ID);

        if (attribute instanceof String)
            return (String) attribute;

        String serviceParameter = ((HttpServletRequest) context.getExternalContext().getNativeRequest())
                .getParameter(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        if (StringUtils.isBlank(serviceParameter))
            serviceParameter = getServiceUrlFromFlowContext(context);

        if (StringUtils.isNotEmpty(serviceParameter))
            serviceParameter = EncodingUtils.urlEncode(serviceParameter);

        return serviceParameter;
    }

    private String getServiceUrlFromFlowContext(RequestContext context) {
        Object attribute = context.getFlowScope().get(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        if (attribute instanceof WebApplicationService) {
            return ((WebApplicationService) attribute).getOriginalUrl();
        } else {
            return null;
        }
    }

    protected void logEvent(StatisticsRecord eventRecord) {
        try {
            this.statistics.collect(eventRecord);
        } catch (Exception ex) {
            log.error("Failed to collect error statistics!", ex);
        }
    }

    protected void logEvent(RequestContext context, AuthenticationType authenticationType, StatisticsOperation eventType) {
        logEvent(StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId(getServiceClientId(context))
                .method(authenticationType)
                .operation(eventType)
                .build()
        );
    }

    protected void logEvent(RequestContext context, Throwable e, AuthenticationType authenticationType) {
        logEvent(StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId(getServiceClientId(context))
                .method(authenticationType)
                .operation(StatisticsOperation.ERROR)
                .error(e != null ? e.getMessage() : null)
                .build()
        );
    }
}
