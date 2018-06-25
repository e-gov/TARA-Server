package ee.ria.sso.config.banklink;

import com.nortal.banklink.authentication.AuthLink;
import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.authentication.link.AuthLinkInfoParser;
import com.nortal.banklink.authentication.link.AuthLinkManagerImpl;
import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthLink;
import com.nortal.banklink.core.packet.NonceManager;
import com.nortal.banklink.link.BankLinkConfig;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.service.banklink.HttpSessionNonceManager;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

@ConditionalOnProperty("banklinks.enabled")
@Configuration
@Slf4j
public class BanklinkConfiguration {

    @Autowired
    private BanklinkConfigurationProvider banklinkConfigurationProvider;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    AuthLinkManager authLinkManager() {
        AuthLinkManagerImpl authLinkManager =  new AuthLinkManagerImpl();
        authLinkManager.setBanklinks(getConfiguredAuthLinks());
        return authLinkManager;
    }

    @Bean
    KeyStore bankLinkKeystore() {
        try {
            KeyStore keystore = KeyStore.getInstance(banklinkConfigurationProvider.getKeystoreType());
            Resource resource = resourceLoader.getResource(banklinkConfigurationProvider.getKeystore());
            keystore.load(resource.getInputStream(), banklinkConfigurationProvider.getKeystorePass().toCharArray());
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load keystore of type " + banklinkConfigurationProvider.getKeystoreType() + " from " + banklinkConfigurationProvider.getKeystore() + "!", e);
        }
    }

    private AuthLink[] getConfiguredAuthLinks() {
        log.info("Start initializing banklink configuration...");
        List<AuthLink> authLinks = new ArrayList<>();
        for (BankEnum bank : banklinkConfigurationProvider.getBankConfiguration().keySet()) {
            authLinks.add(ipizzaAuthLinkLink(bank, bankLinkKeystore()));
        }
        log.info(authLinks.size() + " banklink(s) configured!");
        return authLinks.toArray(new AuthLink[authLinks.size()]);
    }

    private IPizzaStandardAuthLink ipizzaAuthLinkLink(BankEnum forBank, KeyStore keyStore) {
        IPizzaStandardAuthLink authLink = (IPizzaStandardAuthLink) new IPizzaStandardAuthLink(
                forBank.getAuthLinkBank(),
                responseParser(forBank),
                nonceManager(forBank)
        ).config(ipizzaConfig(forBank, keyStore));

        addEncodingFallback(forBank, authLink);

        log.info("Banklink for {} initialized successfully using configuration: {}" , forBank.getName(), banklinkConfigurationProvider.getBankConfiguration().get(forBank));
        return authLink;
    }

    private void addEncodingFallback(BankEnum forBank, IPizzaStandardAuthLink authLink) {
        List<Charset> encodings = banklinkConfigurationProvider.getBankConfiguration().get(forBank).getTryReEncodes();
        if (CollectionUtils.isNotEmpty(encodings))
            authLink.setTryReEncodes(encodings.stream().map(e -> e.displayName()).toArray(String[]::new));
    }

    private NonceManager nonceManager(BankEnum forBank) {
        return new HttpSessionNonceManager(
                banklinkConfigurationProvider.getBankConfiguration().get(forBank).getNonceExpirationInSeconds());
    }

    private AuthLinkInfoParser responseParser(BankEnum forBank) {
        String className = banklinkConfigurationProvider.getBankConfiguration().get(forBank).getResponseParserClass();
        Object authParser = createInstanceOfClass(className);
        if (authParser instanceof AuthLinkInfoParser) {
            return (AuthLinkInfoParser) authParser;
        } else {
            throw new IllegalStateException("Configured class " + banklinkConfigurationProvider.getBankConfiguration().get(forBank).getResponseParserClass() + " must implement interface " + AuthLinkInfoParser.class.getSimpleName());
        }
    }

    private Object createInstanceOfClass(String className) {
        try {
            return Class.forName(className).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Something went wrong with response parser class initializing (class: " + className + ")! Please check your configuration!", e);
        }
    }

    private BankLinkConfig.IPizzaConfig ipizzaConfig(BankEnum bank, KeyStore keyStore) {
        BanklinkConfigurationProvider.BankConfiguration bankConfiguration = banklinkConfigurationProvider.getBankConfiguration().get(bank);
        return BankLinkConfig.IPizzaConfig.ipizza(
                bankConfiguration.getUrl(),
                banklinkConfigurationProvider.getReturnUrl(),
                bankConfiguration.getSenderId(),
                bankConfiguration.getReceiverId(),
                bankPublicKey(bank, bankConfiguration.getPublicKeyAlias(), keyStore),
                clientPrivateKey(keyStore, bankConfiguration.getPrivateKeyAlias(), bankConfiguration.getPrivateKeyPass()));
    }

    private PublicKey bankPublicKey(BankEnum bank, String publicKeyAlias, KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificate(publicKeyAlias);

            if (certificate == null)
                throw new KeyStoreException("No certificate with alias " + bank.name().toLowerCase() + " was found in keystore!");

            return certificate.getPublicKey();
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to load bank certificate for banklink: " + bank + ", please check your configuration!", e);
        }
    }

    private PrivateKey clientPrivateKey(KeyStore keyStore, String keyAlias, String keyPass) {
        try {
            Key key = keyStore.getKey(keyAlias, keyPass.toCharArray());

            if (key == null)
                throw new UnrecoverableKeyException("No private key with alias " + keyAlias + " was found in keystore!");

            if (!key.getAlgorithm().equals("RSA"))
                throw new UnrecoverableKeyException("Key with alias " + keyAlias + " is not an RSA key!");

            return (PrivateKey)key;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Failed to load private key with alias '" + keyAlias + "' from keystore. Please check your configuration!", e);
        }
    }
}
