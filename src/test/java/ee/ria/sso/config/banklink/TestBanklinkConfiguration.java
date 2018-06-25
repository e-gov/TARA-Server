package ee.ria.sso.config.banklink;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.statistics.StatisticsHandler;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@EnableConfigurationProperties
@ComponentScan(basePackages = {
        "ee.ria.sso.config.banklink",
        "ee.ria.sso.service.banklink"
})
@Configuration
@Import(value = {
        TaraResourceBundleMessageSource.class,
        StatisticsHandler.class
})
public class TestBanklinkConfiguration {

    @Bean
    KeyPair mockBankRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.genKeyPair();
        return keyPair;
    }
}