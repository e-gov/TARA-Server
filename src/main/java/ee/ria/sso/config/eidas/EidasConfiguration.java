package ee.ria.sso.config.eidas;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

@ConditionalOnProperty("eidas.enabled")
@Configuration
@Slf4j
public class EidasConfiguration {

    @Autowired
    private EidasConfigurationProvider eidasConfigurationProvider;

    // TODO: this file may not be necessary

}
