package ee.ria.sso.logging;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

@Slf4j
@Component
public class ApplicationPropertiesLogger {

    @EventListener
    public void listenContextRefreshedEvent(ContextRefreshedEvent contextRefreshedEvent) {
        logApplicationProperties((ConfigurableEnvironment) contextRefreshedEvent.getApplicationContext().getEnvironment());
    }

    private void logApplicationProperties(ConfigurableEnvironment environment) {

        Collection<PropertySource<?>> propertySources = new ArrayList<>();

        environment.getPropertySources().forEach(propertySource -> {
            if (propertySource instanceof CompositePropertySource && propertySource.getName().contains("bootstrapProperties")) {
                propertySources.addAll(((CompositePropertySource) propertySource).getPropertySources());
            }
        });

        propertySources
                .forEach(propertySource -> {
                    try {
                        (((CompositePropertySource) propertySource).getPropertySources())
                                .forEach(propSource ->
                                Arrays.stream(((EnumerablePropertySource) propSource).getPropertyNames())
                                        .filter(propertyName -> !(propertyName.contains("pass") || propertyName.contains("key")))
                                        .forEach(property -> log.info("{}: {}", property, StringEscapeUtils.escapeJava(environment.getProperty(property)))));
                    } catch (Exception e) {
                        log.error("{}", e.getMessage());
                    }
                });
    }
}
