package ee.ria.sso.config;

import ee.ria.sso.security.CspDirective;
import ee.ria.sso.security.ResponseCspHeadersEnforcementFilter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@ConditionalOnProperty("security.csp.enabled")
public class TaraCspConfiguration {

    private static final String CONFIG_PREFIX = "security.csp.";

    @Autowired
    private Environment environment;

    @Bean
    public FilterRegistrationBean taraResponseCspHeadersEnforcementFilter() {
        final FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(new ResponseCspHeadersEnforcementFilter(getConfiguredCspDirectives()));
        bean.setUrlPatterns(Collections.singleton("/*"));
        bean.setInitParameters(new HashMap<>());
        bean.setName("taraResponseCspHeadersEnforcementFilter");
        bean.setOrder(Ordered.LOWEST_PRECEDENCE);

        return bean;
    }

    private Map<CspDirective, String> getConfiguredCspDirectives() {
        final Map<CspDirective, String> directives = new LinkedHashMap<>();

        for (final CspDirective directive : CspDirective.values()) {
            final String value = this.environment.getProperty(CONFIG_PREFIX + directive.getCspName(), (String) null);

            if (value != null) {
                directive.validateValue(value);
                directives.put(directive, StringUtils.isNotBlank(value) ? value : null);
            }
        }

        return directives;
    }

}
