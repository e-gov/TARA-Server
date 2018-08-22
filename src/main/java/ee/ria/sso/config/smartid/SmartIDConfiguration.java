package ee.ria.sso.config.smartid;

import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.rest.LoggingFilter;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
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

@ConditionalOnProperty("smart-id.enabled")
@Configuration
public class SmartIDConfiguration {

    @Autowired
    private SmartIDConfigurationProvider confProvider;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public ClientConfig clientConfig() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, confProvider.getConnectionTimeout());
        clientConfig.property(ClientProperties.READ_TIMEOUT, confProvider.getReadTimeout());
        clientConfig.register(new LoggingFilter());
        return clientConfig;
    }

    @Bean
    public SmartIdConnector smartIdConnector() {
        return new SmartIdRestConnector(confProvider.getHostUrl(), clientConfig());
    }

    @Bean
    public AuthenticationResponseValidator authResponseValidator() {
        AuthenticationResponseValidator authResponseValidator = new AuthenticationResponseValidator();
        authResponseValidator.clearTrustedCACertificates();
        addTrustedCACertificates(authResponseValidator);
        return authResponseValidator;
    }

    private void addTrustedCACertificates(AuthenticationResponseValidator authResponseValidator) {
        confProvider.getTrustedCaCertificates().forEach(certificateName ->
                {
                    try {
                        X509Certificate certificate = readCertFromResource(certificateName);
                        authResponseValidator.addTrustedCACertificate(certificate);
                    } catch (CertificateException | IOException e) {
                        throw new IllegalArgumentException("Failed to read certificate from file " + certificateName);
                    }
                }
        );
    }

    private X509Certificate readCertFromResource(String resourceName) throws IOException, CertificateException {
        String resourcePath = confProvider.getTrustedCaCertificatesLocation() + "/" + resourceName;
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
