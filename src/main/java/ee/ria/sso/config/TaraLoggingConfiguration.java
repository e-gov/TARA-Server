package ee.ria.sso.config;

import ee.ria.sso.logging.IncidentLoggingMDCServletFilter;
import ee.ria.sso.logging.RequestContextAsFirstParameterResourceResolver;
import org.apereo.cas.audit.spi.DefaultDelegatingAuditTrailManager;
import org.apereo.cas.audit.spi.DelegatingAuditTrailManager;
import org.apereo.cas.audit.spi.config.CasCoreAuditConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.inspektr.audit.AuditActionContext;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.apereo.inspektr.audit.support.Slf4jLoggingAuditTrailManager;
import org.hjson.JsonObject;
import org.hjson.Stringify;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class TaraLoggingConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Bean
    public DelegatingAuditTrailManager auditTrailManager() {
        final TaraSlf4jLoggingAuditTrailManager mgmr = new TaraSlf4jLoggingAuditTrailManager();
        mgmr.setUseSingleLine(casProperties.getAudit().isUseSingleLine());
        mgmr.setEntrySeparator(casProperties.getAudit().getSinglelineSeparator());
        mgmr.setAuditFormat(casProperties.getAudit().getAuditFormat());
        return new DefaultDelegatingAuditTrailManager(mgmr);
    }

    @Bean
    public Map<String, AuditResourceResolver> auditResourceResolverMap() {
        final Map<String, AuditResourceResolver> map = new CasCoreAuditConfiguration().auditResourceResolverMap();
        map.put("TARA_AUTHENTICATION_RESOURCE_RESOLVER", new RequestContextAsFirstParameterResourceResolver());
        return map;
    }

    @Bean
    public FilterRegistrationBean incidentLoggingMDCServletFilter() {
        final Map<String, String> initParams = new HashMap<>();
        final FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(new IncidentLoggingMDCServletFilter());
        bean.setUrlPatterns(Collections.singleton("/*"));
        bean.setInitParameters(initParams);
        bean.setName("incidentLoggingMDCServletFilter");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return bean;
    }

    private class TaraSlf4jLoggingAuditTrailManager extends Slf4jLoggingAuditTrailManager {

        private final Logger log = LoggerFactory.getLogger("auditLog");
        private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss,SSSZ");

        public void record(final AuditActionContext auditActionContext) {

            if (casProperties.getAudit().getAuditFormat() == AuditFormats.JSON)
                log.info(getJsonObjectForAudit(auditActionContext).toString(Stringify.PLAIN));
            else
                log.info(toString(auditActionContext));
        }

        @Override
        protected JsonObject getJsonObjectForAudit(final AuditActionContext auditActionContext) {
            final JsonObject jsonObject = new JsonObject()
                    .add("action", auditActionContext.getActionPerformed())
                    .add("who", auditActionContext.getPrincipal())
                    .add("what", auditActionContext.getResourceOperatedUpon())
                    .add("when", dateTimeFormatter.format(auditActionContext.getWhenActionWasPerformed().toInstant().atZone(ZoneId.systemDefault())))
                    .add("clientIpAddress", auditActionContext.getClientIpAddress())
                    .add("serverIpAddress", auditActionContext.getServerIpAddress())
                    .add("application", auditActionContext.getApplicationCode());
            return jsonObject;
        }
    }
}
