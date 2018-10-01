package ee.ria.sso.config;

import ee.ria.sso.security.ResponseCspHeadersEnforcementFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

@Configuration
@EnableConfigurationProperties(TaraProperties.class)
public class TaraCspConfiguration {

    @Autowired
    private TaraProperties taraProperties;

    @Bean
    public FilterRegistrationBean taraResponseCspHeadersEnforcementFilter() {
        final FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(new ResponseCspHeadersEnforcementFilter(getAllowedSourceTypes(), getAllowedFormActions()));
        bean.setUrlPatterns(Collections.singleton("/*"));
        bean.setInitParameters(new HashMap<>());
        bean.setName("taraResponseCspHeadersEnforcementFilter");
        bean.setOrder(Ordered.LOWEST_PRECEDENCE);

        return bean;
    }

    private List<ResponseCspHeadersEnforcementFilter.FetchDirective> getAllowedSourceTypes() {
        return Arrays.asList(
                ResponseCspHeadersEnforcementFilter.FetchDirective.CONNECT_SRC,
                ResponseCspHeadersEnforcementFilter.FetchDirective.FONT_SRC,
                ResponseCspHeadersEnforcementFilter.FetchDirective.IMG_SRC,
                ResponseCspHeadersEnforcementFilter.FetchDirective.SCRIPT_SRC,
                ResponseCspHeadersEnforcementFilter.FetchDirective.STYLE_SRC
        );
    }

    private List<String> getAllowedFormActions() {
        return Collections.emptyList();
    }

}
