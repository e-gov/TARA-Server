package ee.ria.sso.config.eidas;

import ee.ria.sso.service.eidas.EidasAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

@Configuration
@ConditionalOnProperty("eidas.enabled")
@Slf4j
public class EidasConfiguration {

    @Autowired
    private EidasConfigurationProvider eidasConfigurationProvider;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    EidasAuthenticator eidasAuthenticator() {
        return new EidasAuthenticator(eidasConfigurationProvider, buildHttpClient());
    }

    private CloseableHttpClient buildHttpClient() {
        HttpClientBuilder httpClientBuilder = HttpClients.custom()
                .setConnectionManager(pooledConnectionManager());

        if (eidasConfigurationProvider.isClientCertificateEnabled()) {
            httpClientBuilder.setSSLContext(buildSSLContext());
        }

        return httpClientBuilder.build();
    }

    private PoolingHttpClientConnectionManager pooledConnectionManager() {
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(eidasConfigurationProvider.getConnectionPool().getMaxTotal());
        connectionManager.setDefaultMaxPerRoute(eidasConfigurationProvider.getConnectionPool().getMaxPerRoute());
        return connectionManager;
    }

    private SSLContext buildSSLContext() {
        try {
            return SSLContexts.custom()
                  .loadKeyMaterial(loadEidasAuthenticatorKeystore(), eidasConfigurationProvider.getClientCertificateKeystorePass().toCharArray())
                  .build();
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Failed to construct SSLContext", e);
        }
    }

    private KeyStore loadEidasAuthenticatorKeystore() {
        try {
            KeyStore keystore = KeyStore.getInstance(eidasConfigurationProvider.getClientCertificateKeystoreType());
            Resource resource = resourceLoader.getResource(eidasConfigurationProvider.getClientCertificateKeystore());
            try (InputStream inputStream = resource.getInputStream()) {
                keystore.load(inputStream, eidasConfigurationProvider.getClientCertificateKeystorePass().toCharArray());
            }
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException(String.format(
                    "Could not load keystore of type %s from %s!",
                    eidasConfigurationProvider.getClientCertificateKeystoreType(),
                    eidasConfigurationProvider.getClientCertificateKeystore()
            ), e);
        }
    }
}