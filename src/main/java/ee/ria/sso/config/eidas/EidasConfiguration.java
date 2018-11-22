package ee.ria.sso.config.eidas;

import ee.ria.sso.service.eidas.EidasAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

@Configuration
@ConditionalOnProperty("eidas.enabled")
@Slf4j
public class EidasConfiguration {

    @Autowired
    private EidasConfigurationProvider eidasConfigurationProvider;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    EidasAuthenticator eidasAuthenticator() throws GeneralSecurityException {
        if (eidasConfigurationProvider.isClientCertificateEnabled()) {
            return new EidasAuthenticator(eidasConfigurationProvider, loadEidasAuthenticatorKeystore());
        } else {
            return new EidasAuthenticator(eidasConfigurationProvider);
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
