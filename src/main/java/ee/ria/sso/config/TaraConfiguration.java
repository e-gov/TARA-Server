package ee.ria.sso.config;

import ee.ria.sso.InsecureTrustManager;
import org.apache.commons.lang.StringUtils;
import org.apereo.cas.util.AsciiArtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.*;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.annotation.PostConstruct;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.*;

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
    private final int paddingSize = 225;

    public TaraConfiguration(TaraProperties taraProperties) {
        this.taraProperties = taraProperties;
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
}
