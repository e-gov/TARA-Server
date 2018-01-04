package org.apereo.cas.config;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.web.Log4jServletContextListener;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.mvc.ParameterizableViewController;
import org.springframework.web.servlet.mvc.SimpleControllerHandlerAdapter;
import org.springframework.web.servlet.theme.ThemeChangeInterceptor;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Configuration("casWebAppConfiguration")
@EnableConfigurationProperties({CasConfigurationProperties.class})
public class CasWebAppConfiguration extends WebMvcConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(CasWebAppConfiguration.class);

    @Autowired
    private LocaleChangeInterceptor localeChangeInterceptor;

    @Autowired
    private CasConfigurationProperties casProperties;

    public CasWebAppConfiguration() {
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(this.localeChangeInterceptor);
    }

    @RefreshScope
    @Bean
    public ThemeChangeInterceptor themeChangeInterceptor() {
        ThemeChangeInterceptor bean = new ThemeChangeInterceptor();
        bean.setParamName(this.casProperties.getTheme().getParamName());
        return bean;
    }

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver bean = new SessionLocaleResolver();
        String locale = this.casProperties.getLocale().getDefaultValue();
        this.log.debug("Setting default locale to [{}]", locale);
        bean.setDefaultLocale(new Locale(locale));
        return bean;
    }

    @Bean
    public Map serviceThemeResolverSupportedBrowsers() {
        Map<String, String> map = new HashMap();
        map.put(".*iPhone.*", "iphone");
        map.put(".*Android.*", "android");
        map.put(".*Safari.*Pre.*", "safari");
        map.put(".*iPhone.*", "iphone");
        map.put(".*Nokia.*AppleWebKit.*", "nokiawebkit");
        return map;
    }

    @Bean
    protected Controller rootController() {
        return new ParameterizableViewController() {
            protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
                String queryString = request.getQueryString();
                String url = request.getContextPath() + "/login" + (queryString != null ? '?' + queryString : "");
                return new ModelAndView(new RedirectView(response.encodeURL(url)));
            }
        };
    }

    @Bean
    public ServletListenerRegistrationBean log4jServletContextListener() {
        ServletListenerRegistrationBean bean = new ServletListenerRegistrationBean();
        bean.setEnabled(true);
        bean.setName("log4jServletContextListener");
        bean.setListener(new Log4jServletContextListener());
        return bean;
    }

    @Bean
    public SimpleUrlHandlerMapping handlerMapping() {
        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
        Controller root = this.rootController();
        mapping.setOrder(1);
        mapping.setAlwaysUseFullPath(true);
        mapping.setRootHandler(root);
        Map urls = new HashMap();
        urls.put("/", root);
        mapping.setUrlMap(urls);
        return mapping;
    }

    @Bean
    public SimpleControllerHandlerAdapter simpleControllerHandlerAdapter() {
        return new SimpleControllerHandlerAdapter();
    }

}
