package ee.ria.sso.config.idcard;

import ee.ria.sso.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

@ConditionalOnProperty("id-card.enabled")
@Configuration
@Slf4j
public class IDCardConfiguration {

    @Autowired
    private IDCardConfigurationProvider configurationProvider;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    @ConditionalOnProperty("id-card.ocsp-enabled")
    public Map<String, X509Certificate> idCardTrustedCertificatesMap() {
        final Map<String, X509Certificate> trustedCertificates = new LinkedHashMap<>();

        configurationProvider.getOcspCertificates().forEach(ocspCertificate -> {
            try {
                final X509Certificate certificate = readCertFromResource(ocspCertificate);
                final String commonName = X509Utils.getSubjectCNFromCertificate(certificate);
                trustedCertificates.put(commonName, certificate);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to read certificate " + ocspCertificate, e);
            }
        });

        return trustedCertificates;
    }

    private X509Certificate readCertFromResource(String resourceName) throws CertificateException, IOException {
        String resourcePath = configurationProvider.getOcspCertificateLocation() + "/" + resourceName;
        Resource resource = resourceLoader.getResource(resourcePath);
        if (!resource.exists()) {
            throw new IllegalArgumentException("Could not find resource " + resourcePath);
        }

        try (InputStream inputStream = resource.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

}
