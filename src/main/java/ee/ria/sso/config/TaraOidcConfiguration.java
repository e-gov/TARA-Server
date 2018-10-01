package ee.ria.sso.config;

import ee.ria.sso.validators.OidcAuthorizeRequestValidationServletFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class TaraOidcConfiguration {

    @Bean
    public FilterRegistrationBean oidcAuthorizeCheckingServletFilter() {
        final Map<String, String> initParams = new HashMap<>();
        final FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(new OidcAuthorizeRequestValidationServletFilter());
        bean.setUrlPatterns(Collections.singleton("/oidc/authorize"));
        bean.setInitParameters(initParams);
        bean.setName("oidcAuthorizeCheckingServletFilter");
        bean.setOrder(Ordered.LOWEST_PRECEDENCE);
        return bean;
    }
}
