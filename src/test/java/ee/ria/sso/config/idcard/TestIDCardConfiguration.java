package ee.ria.sso.config.idcard;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.validators.OCSPValidator;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.idcard",
        "ee.ria.sso.service.idcard",
        "ee.ria.sso.validators"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class
})
public class TestIDCardConfiguration {

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    X509Certificate mockIDCardUserCertificate() throws CertificateException, IOException {
        String filePath = "classpath:id-card/47101010033.pem";
        Resource file = resourceLoader.getResource(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("Could not find file " + filePath);
        }

        try (InputStream inputStream = file.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

    @Bean
    @Primary
    @ConditionalOnProperty("id-card.enabled")
    OCSPValidator mockOCSPValidator() {
        OCSPValidator ocspValidator = Mockito.mock(OCSPValidator.class);
        return ocspValidator;
    }

}
