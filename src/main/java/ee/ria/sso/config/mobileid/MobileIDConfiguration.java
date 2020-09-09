package ee.ria.sso.config.mobileid;

import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationClient;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTAuthClient;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidClient;
import ee.sk.mid.rest.MidLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@ConditionalOnProperty("mobile-id.enabled")
@Configuration
@Slf4j
public class MobileIDConfiguration {

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    private final MidAuthenticationResponseValidator validator = new MidAuthenticationResponseValidator();

    @Bean
    public MobileIDAuthenticationClient constructAuthenticationClient(ManagerService managerService, ResourceLoader resourceLoader) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        log.info("Initializing REST protocol based authentication client for Mobile-ID REST service");
        addTrustedCACertificates(resourceLoader);
        return new MobileIDRESTAuthClient(configurationProvider, midClient(), managerService, validator);
    }

    @Bean
    public MobileIDAuthenticationService mobileIDAuthenticationService(StatisticsHandler statisticsHandler, ManagerService managerService, ResourceLoader resourceLoader) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return new MobileIDAuthenticationService(
                statisticsHandler, configurationProvider, constructAuthenticationClient(managerService, resourceLoader));
    }

    private MidClient midClient() throws NoSuchAlgorithmException {
        return MidClient.newBuilder()
                .withHostUrl(configurationProvider.getHostUrl())
                .withRelyingPartyUUID(configurationProvider.getRelyingPartyUuid())
                .withRelyingPartyName(configurationProvider.getRelyingPartyName())
                .withNetworkConnectionConfig(clientConfig())
                .withLongPollingTimeoutSeconds(configurationProvider.getSessionStatusSocketOpenDuration())
                .withSslContext(SSLContext.getDefault())
                .build();
    }

    private ClientConfig clientConfig() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, configurationProvider.getConnectionTimeout());
        clientConfig.property(ClientProperties.READ_TIMEOUT, configurationProvider.getReadTimeout());
        clientConfig.register(new MidLoggingFilter());
        return clientConfig;
    }

    private void addTrustedCACertificates(ResourceLoader resourceLoader) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        Resource resource = resourceLoader.getResource(configurationProvider.getTruststore());
        if (!resource.exists()) {
            throw new IllegalArgumentException("Could not find resource " + resource.getDescription());
        }

        InputStream is = resource.getInputStream();
        KeyStore keyStore = KeyStore.getInstance(configurationProvider.getTruststoreType());
        keyStore.load(is, configurationProvider.getTruststorePass().toCharArray());

        Enumeration<String> keyStoreAliases = keyStore.aliases();
        while (keyStoreAliases.hasMoreElements()) {
            String keyStoreAlias = keyStoreAliases.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyStoreAlias);
            validator.addTrustedCACertificate(cert);
        }
    }
}
