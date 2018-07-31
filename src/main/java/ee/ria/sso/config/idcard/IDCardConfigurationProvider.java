package ee.ria.sso.config.idcard;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.NotBlank;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@ConditionalOnProperty("idcard.enabled")
@Configuration
@ConfigurationProperties(prefix = "idcard")
@Validated
@Getter
@Setter
@Slf4j
public class IDCardConfigurationProvider {

    private boolean ocspEnabled;

    private String ocspUrl = "http://demo.sk.ee/ocsp";
    private String ocspCertificateDirectory;
    private String ocspCertificates;

    private Map<String, X509Certificate> issuerCertificates = new HashMap<>();

    @PostConstruct
    public void init() {
        if (this.ocspEnabled) {
            Map<String, String> filenameAndCertCNMap = Arrays.stream(this.ocspCertificates.split(","))
                    .map(prop -> prop.split(":")).collect(Collectors.toMap(e -> e[0], e -> e[1]));

            for (Map.Entry<String, String> entry : filenameAndCertCNMap.entrySet()) {
                this.issuerCertificates.put(entry.getKey(), this.readCert(entry.getValue()));
            }
        }
    }

    private X509Certificate readCert(String filename) {
        String fullPath = this.ocspCertificateDirectory + "/" + filename;
        try ( FileInputStream fis = new FileInputStream(fullPath) ) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

}
