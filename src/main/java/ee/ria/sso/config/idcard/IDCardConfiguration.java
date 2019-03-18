package ee.ria.sso.config.idcard;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.service.idcard.IDCardAuthenticationService;
import ee.ria.sso.service.idcard.OCSPConfigurationResolver;
import ee.ria.sso.service.idcard.OCSPValidator;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

@ConditionalOnProperty("id-card.enabled")
@Configuration
@Slf4j
public class IDCardConfiguration {

    @Autowired
    private IDCardConfigurationProvider configurationProvider;

    @Bean
    KeyStore idcardKeystore(ResourceLoader resourceLoader) {
        try {
            KeyStore keystore = KeyStore.getInstance(configurationProvider.getTruststoreType());
            Resource resource = resourceLoader.getResource(configurationProvider.getTruststore());
            try (InputStream inputStream = resource.getInputStream()) {
                keystore.load(inputStream, configurationProvider.getTruststorePass().toCharArray());
            }
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load truststore of type " + configurationProvider.getTruststoreType() + " from " + configurationProvider.getTruststore() + "!", e);
        }
    }

    @Bean
    public Map<String, X509Certificate> idCardTrustedCertificatesMap(KeyStore idcardKeystore) {
        final Map<String, X509Certificate> trustedCertificates = new LinkedHashMap<>();

        try {
            PKIXParameters params = new PKIXParameters(idcardKeystore);
            Iterator it = params.getTrustAnchors().iterator();
            while( it.hasNext() ) {
                TrustAnchor ta = (TrustAnchor)it.next();
                final String commonName = X509Utils.getSubjectCNFromCertificate(ta.getTrustedCert());
                trustedCertificates.put(commonName, ta.getTrustedCert());
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: "  + e.getMessage(), e);
        }

        return trustedCertificates;
    }

    @Bean
    public IDCardAuthenticationService idCardAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                                                   StatisticsHandler statistics,
                                                                   IDCardConfigurationProvider configurationProvider,
                                                                   OCSPValidator ocspValidator) {

        return new IDCardAuthenticationService(messageSource, statistics, configurationProvider, ocspValidator);
    }

    @Bean
    public OCSPConfigurationResolver ocspConfigurationResolver(IDCardConfigurationProvider configurationProvider) {
        return new OCSPConfigurationResolver(configurationProvider);
    }

    @Bean
    public OCSPValidator ocspValidator(Map<String, X509Certificate> idCardTrustedCertificatesMap, OCSPConfigurationResolver ocspConfigurationResolver) {
        return new OCSPValidator(idCardTrustedCertificatesMap, ocspConfigurationResolver);
    }
}
