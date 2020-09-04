package ee.ria.sso.config.mobileid;

import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationClient;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.mobileid.rest.MobileIDRESTAuthClient;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.mid.MidClient;
import ee.sk.mid.rest.MidLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@ConditionalOnProperty("mobile-id.enabled")
@Configuration
@Slf4j
public class MobileIDConfiguration {

    @Autowired
    private StatisticsHandler statisticsHandler;

    @Autowired
    private MobileIDConfigurationProvider configurationProvider;

    @Autowired
    private ManagerService managerService;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public MobileIDAuthenticationClient constructAuthenticationClient() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        log.info("Initializing REST protocol based authentication client for Mobile-ID REST service");
        return new MobileIDRESTAuthClient(configurationProvider, midClient(), managerService, resourceLoader);
    }

    @Bean
    public MobileIDAuthenticationService mobileIDAuthenticationService() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        return new MobileIDAuthenticationService(
                statisticsHandler, configurationProvider, constructAuthenticationClient());
    }

    private MidClient midClient() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init((KeyStore) null);
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        return MidClient.newBuilder()
                .withHostUrl(configurationProvider.getHostUrl())
                .withRelyingPartyUUID(configurationProvider.getRelyingPartyUuid())
                .withRelyingPartyName(configurationProvider.getRelyingPartyName())
                .withNetworkConnectionConfig(clientConfig())
                .withLongPollingTimeoutSeconds(configurationProvider.getSessionStatusSocketOpenDuration())
                .withSslContext(sslContext)
                .build();
    }

    private ClientConfig clientConfig() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, configurationProvider.getConnectionTimeout());
        clientConfig.property(ClientProperties.READ_TIMEOUT, configurationProvider.getReadTimeout());
        clientConfig.register(new MidLoggingFilter());
        return clientConfig;
    }
}
