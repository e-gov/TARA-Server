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

import java.io.IOException;
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

    @Bean
    public MobileIDAuthenticationClient constructAuthenticationClient() throws IOException, CertificateException {
        log.info("Initializing REST protocol based authentication client for Mobile-ID REST service");
        return new MobileIDRESTAuthClient(configurationProvider, midClient(), managerService);
    }

    @Bean
    public MobileIDAuthenticationService mobileIDAuthenticationService() throws IOException, CertificateException {
        return new MobileIDAuthenticationService(
                statisticsHandler, configurationProvider, constructAuthenticationClient());
    }

    private MidClient midClient() {
        return MidClient.newBuilder()
                .withHostUrl(configurationProvider.getHostUrl())
                .withRelyingPartyUUID(configurationProvider.getRelyingPartyUuid())
                .withRelyingPartyName(configurationProvider.getRelyingPartyName())
                .withNetworkConnectionConfig(clientConfig())
                .withLongPollingTimeoutSeconds(configurationProvider.getSessionStatusSocketOpenDuration())
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