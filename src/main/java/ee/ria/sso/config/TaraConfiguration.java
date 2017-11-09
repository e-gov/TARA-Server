package ee.ria.sso.config;

import java.security.SecureRandom;

import javax.annotation.PostConstruct;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apereo.cas.util.AsciiArtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import ee.ria.sso.InsecureTrustManager;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)
@ComponentScan(basePackages = {"ee.ria.sso", "org.jasig.cas"})
public class TaraConfiguration {

    private final Logger log = LoggerFactory.getLogger(TaraConfiguration.class);
    private final TaraProperties taraProperties;
    private final int paddingSize = 225;

    public TaraConfiguration(TaraProperties taraProperties) {
        this.taraProperties = taraProperties;
    }

    @PostConstruct
    protected void init() throws Exception {
        if (this.taraProperties.getEnvironment().isDevelopment()) {
            StringBuilder sb = new StringBuilder();
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{new InsecureTrustManager()}, new SecureRandom());
            SSLContext.setDefault(sslContext);
            sb.append(StringUtils.rightPad("<x> Using insecure trust manager configuration ", this.paddingSize, "-"));
            AsciiArtUtils.printAsciiArtWarning(this.log, "NB! DEVELOPMENT MODE ACTIVATED", sb.toString());
        }
    }

}
