package ee.ria.sso.config;

import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import ee.ria.sso.logging.AccessTokenRequestResourceResolver;
import ee.ria.sso.logging.IncidentLoggingMDCServletFilter;
import ee.ria.sso.logging.OAuthCodeResourceResolver;
import ee.ria.sso.logging.RequestContextAsFirstParameterResourceResolver;
import org.apereo.cas.audit.AuditTrailExecutionPlan;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlan;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.inspektr.audit.AuditActionContext;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.apereo.inspektr.audit.support.Slf4jLoggingAuditTrailManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class TaraLoggingConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    private AuditTrailRecordResolutionPlan auditTrailRecordResolutionPlan;

    @Autowired
    @Qualifier("auditTrailExecutionPlan")
    private AuditTrailExecutionPlan  auditTrailExecutionPlan;

    @PostConstruct
    public void init() {
        if (auditTrailExecutionPlan != null) {
            auditTrailExecutionPlan.registerAuditTrailManager(new TaraSlf4jLoggingAuditTrailManager());
        }
    }

    @Bean
    public Map<String, AuditResourceResolver> auditResourceResolverMap() {
        final Map<String, AuditResourceResolver> map = new HashMap<>();
        map.put("TARA_AUTHENTICATION_RESOURCE_RESOLVER", new RequestContextAsFirstParameterResourceResolver());
        map.put("TARA_ACCESS_TOKEN_REQUEST_RESOURCE_RESOLVER", new AccessTokenRequestResourceResolver());
        map.put("TARA_CREATE_OAUTH_CODE_RESOURCE_RESOLVER", new OAuthCodeResourceResolver());
        auditTrailRecordResolutionPlan.registerAuditResourceResolvers(map);
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
        bean.setOrder(Integer.MIN_VALUE + 51); // Spring's SessionRepositoryFilter must precede the IncidentLoggingMDCServletFilter
        return bean;
    }

    private class TaraSlf4jLoggingAuditTrailManager extends Slf4jLoggingAuditTrailManager {

        private final Logger log = LoggerFactory.getLogger("auditLog");
        private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
        private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss,SSSZ");

        public void record(final AuditActionContext auditActionContext) {

            try {
                if (casProperties.getAudit().getSlf4j().getAuditFormat() == AuditFormats.JSON) {
                    final ObjectWriter writer = this.mapper.writer(new MinimalPrettyPrinter());
                    log.info(writer.writeValueAsString(getJsonObjectForAudit(auditActionContext)));
                } else {
                    log.info(toString(auditActionContext));
                }
            } catch (final Exception e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }

        @Override
        protected Map getJsonObjectForAudit(final AuditActionContext auditActionContext) {
            final Map jsonObject = new LinkedHashMap();
            jsonObject.put("action", auditActionContext.getActionPerformed());
            jsonObject.put("who", auditActionContext.getPrincipal());
            jsonObject.put("what", auditActionContext.getResourceOperatedUpon());
            jsonObject.put("when", dateTimeFormatter.format(auditActionContext.getWhenActionWasPerformed().toInstant().atZone(ZoneId.systemDefault())));
            jsonObject.put("clientIpAddress", auditActionContext.getClientIpAddress());
            jsonObject.put("serverIpAddress", auditActionContext.getServerIpAddress());
            jsonObject.put("application", auditActionContext.getApplicationCode());
            return jsonObject;
        }
    }
}
