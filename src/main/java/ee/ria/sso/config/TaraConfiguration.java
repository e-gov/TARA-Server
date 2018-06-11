package ee.ria.sso.config;

import com.nortal.banklink.authentication.AuthLink;
import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.authentication.link.AuthLinkManagerImpl;
import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthLink;
import com.nortal.banklink.link.Bank;
import com.nortal.banklink.link.BankLinkConfig;
import ee.ria.sso.InsecureTrustManager;
import ee.ria.sso.authentication.BankEnum;
import org.apache.commons.lang.StringUtils;
import org.apereo.cas.util.AsciiArtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.*;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.Assert;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.*;
import java.security.cert.Certificate;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Configuration
@PropertySource("classpath:dynamic.properties")
@EnableAspectJAutoProxy(proxyTargetClass = true)
@ComponentScan(basePackages = {"ee.ria.sso", "org.jasig.cas"})
public class TaraConfiguration extends WebMvcConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(TaraConfiguration.class);
    private final TaraProperties taraProperties;
    private final ResourceLoader resourceLoader;
    private final int paddingSize = 225;

    public TaraConfiguration(TaraProperties taraProperties, ResourceLoader resourceLoader) {
        this.taraProperties = taraProperties;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    protected void init() throws Exception {
        if (this.taraProperties.getApplication().isDevelopment()) {
            StringBuilder sb = new StringBuilder();
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{new InsecureTrustManager()}, new SecureRandom());
            SSLContext.setDefault(sslContext);
            sb.append(StringUtils.rightPad("<x> Using insecure trust manager configuration ", this.paddingSize, "-"));
            AsciiArtUtils.printAsciiArtWarning(this.log, "NB! DEVELOPMENT MODE ACTIVATED", sb.toString());
        }
    }

    @Bean
    AuthLinkManager authLinkManager() {
        return new AuthLinkManagerImpl() {
            @Override
            @Resource
            public void setBanklinks(AuthLink[] authLinks) {
                super.setBanklinks(authLinks);
            }
        };
    }

    @Bean
    KeyStore bankLinkKeystore() {
        String keyStore = taraProperties.getBanklinkKeyStore();
        String keyStoreType = taraProperties.getBanklinkKeyStoreType();
        String keyStorePass = taraProperties.getBanklinkKeyStorePass();

        Assert.notNull( keyStore, "Could not determine keystore for banklinks. Please check your configuration");
        Assert.notNull( keyStorePass, "Could not determine keystore password for banklinks. Please check your configuration");

        try {
            KeyStore keystore = KeyStore.getInstance(keyStoreType == null ? KeyStore.getDefaultType() : keyStoreType);
            org.springframework.core.io.Resource resource = resourceLoader.getResource(keyStore);

            keystore.load(resource.getInputStream(), keyStorePass.toCharArray());
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load keystore of type " + keyStoreType + " from " + keyStore + "!", e);
        }
    }

    @Bean
    AuthLink luminorEstAuthLink(KeyStore keyStore) {
        IPizzaStandardAuthLink nordeaLink = ipizzaAuthLinkLink(BankEnum.LUMINOR, keyStore);
        nordeaLink.setTryReEncodes(new String[] { "ISO-8859-1", "WINDOWS-1252" });
        return nordeaLink;
    }

    @Bean
    AuthLink danskeEstAuthLink(KeyStore keyStore) {
        return ipizzaAuthLinkLink(BankEnum.DANSKE, keyStore);
    }

    @Bean
    AuthLink sebEstAuthLink(KeyStore keyStore) {
        return ipizzaAuthLinkLink(BankEnum.SEB, keyStore);
    }

    @Bean
    AuthLink swedbankEstAuthLink(KeyStore keyStore) {
        return ipizzaAuthLinkLink(BankEnum.SWEDBANK, keyStore);
    }

    @Bean
    AuthLink lhvAuthLink(KeyStore keyStore) {
        return ipizzaAuthLinkLink(BankEnum.LHV, keyStore);
    }

    @Bean
    AuthLink coopAuthLink(KeyStore keyStore) {
        return ipizzaAuthLinkLink(BankEnum.COOP, keyStore);
    }

    private IPizzaStandardAuthLink ipizzaAuthLinkLink(BankEnum forBank, KeyStore keyStore) {
        return (IPizzaStandardAuthLink) new IPizzaStandardAuthLink(forBank.getAuthLinkBank()).config(ipizza(forBank, keyStore));
    }

    private BankLinkConfig.IPizzaConfig ipizza(BankEnum bank, KeyStore keyStore) {
        return BankLinkConfig.IPizzaConfig.ipizza(cfg(bank.getUrlCode()), taraProperties.getBanklinkReturnUrl(), cfg(bank.getVkSenderIdCode()), cfg(bank.getVkRecIdCode()),
                bankPub(bank, keyStore), clientPriv(bank, keyStore));
    }

    private PublicKey bankPub(BankEnum bank, KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificate(bank.name().toLowerCase());

            if (certificate == null)
                throw new KeyStoreException("No certificate with alias " + bank.name().toLowerCase() + " was found in keystore!");

            return certificate.getPublicKey();
        } catch (KeyStoreException e) {
            log.error("Failed to load bank certificate for banklink: " + bank + ", banklink validation for this bank will not work");
            if (log.isTraceEnabled())
                log.warn("", e);
            return null;
        }
    }

    private PrivateKey clientPriv(BankEnum bank, KeyStore keyStore) {
        try {
            String keyAlias = bank.name().toLowerCase() + "_priv";
            Key key = keyStore.getKey(keyAlias, taraProperties.getBanklinkKeyStorePass().toCharArray());

            if (key == null)
                throw new UnrecoverableKeyException("No private key with alias " + keyAlias + " was found in keystore!");

            if (!key.getAlgorithm().equals("RSA"))
                throw new UnrecoverableKeyException("Key with alias " + keyAlias + " is not an RSA key!");

            return (PrivateKey)key;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error("Failed to load private key for banklink: " + bank + ", banklink signing for this bank will not work");
            if (log.isTraceEnabled())
                log.warn("", e);
            return null;
        }
    }

    private String cfg(String key) {
        return taraProperties.getEnvironment().getProperty(key);
    }
}
