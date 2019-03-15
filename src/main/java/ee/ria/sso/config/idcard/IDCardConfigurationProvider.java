package ee.ria.sso.config.idcard;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.Min;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@ConditionalOnProperty("id-card.enabled")
@Configuration
@ConfigurationProperties(prefix = "id-card")
@Validated
@Getter
@Setter
@Slf4j
public class IDCardConfigurationProvider {

    private String truststore;

    private String truststoreType = "PKCS12";

    private String truststorePass;

    private boolean ocspEnabled = true;

    @Valid
    private List<Ocsp> ocsp;

    @Valid
    private List<Ocsp> fallbackOcsp;

    @PostConstruct
    public void validateConfiguration() {
        if (this.ocspEnabled) {
            Set<String> duplicateNames = getFindDuplicateConfigurations();
            Assert.isTrue(duplicateNames.isEmpty(), "Multiple OCSP configurations detected for issuer's with CN's: " + duplicateNames + ". Please check your configuration!");
            Assert.notNull(this.truststore, "Keystore location cannot be empty when OCSP is enabled!");
            Assert.notNull(this.truststorePass, "Keystore password cannot be empty when OCSP is enabled!");

        } else {
            log.warn("OCSP verification has been DISABLED! User certificates will not be checked for revocation!");
        }
        log.info("Using id-card configuration: " + this);
    }

    @Data
    @NoArgsConstructor
    @ToString
    public static class Ocsp {
        public static final long DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS = 2L;
        public static final long DEFAULT_RESPONSE_LIFETIME_IN_SECONDS = 900L;
        public static final int DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS = 3 * 1000;
        public static final int DEFAULT_READ_TIMEOUT_IN_MILLISECONDS = 3 * 1000;

        @NotEmpty
        private List<String> issuerCn;
        @NotEmpty
        private String url;

        private boolean nonceDisabled = false;
        @Min(0L)
        private long acceptedClockSkewInSeconds = DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS;
        @Min(0L)
        private long responseLifetimeInSeconds = DEFAULT_RESPONSE_LIFETIME_IN_SECONDS;
        @Min(0L)
        private int connectTimeoutInMilliseconds = DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS;
        @Min(0L)
        private int readTimeoutInMilliseconds = DEFAULT_READ_TIMEOUT_IN_MILLISECONDS;

        private String responderCertificateCn;
    }

    private Set<String> getFindDuplicateConfigurations() {
        Set<String> names = new HashSet<>();
        return ocsp.stream()
                .flatMap(item -> item.getIssuerCn().stream())
                .filter(cn -> !names.add(cn))
                .collect(Collectors.toSet());
    }
}
