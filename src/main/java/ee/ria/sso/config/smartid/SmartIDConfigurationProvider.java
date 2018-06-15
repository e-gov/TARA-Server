package ee.ria.sso.config.smartid;

import ee.sk.smartid.HashType;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.NotBlank;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

@Component
@ConditionalOnProperty("smart-id.enabled")
@Configuration
@ConfigurationProperties(prefix = "smart-id")
@Validated
@Getter
@Setter
public class SmartIDConfigurationProvider {

    private static final HashType DEFAULT_AUTHENTICATION_HASH_TYPE = HashType.SHA512;
    private static final int DEFAULT_CONNECTION_TIMEOUT = 5000;
    private static final int DEFAULT_READ_TIMEOUT = 30000;
    private static final int DEFAULT_SESSION_STATUS_SOCKET_OPEN_DURATION = 3000;

    @NotBlank
    private String relyingPartyUuid;

    @NotBlank
    private String relyingPartyName;

    @NotBlank
    private String hostUrl;

    @NotBlank
    private String trustedCaCertificatesLocation;

    @NotNull
    private List<String> trustedCaCertificates = new ArrayList<>();

    @NotBlank
    private String authenticationConsentDialogDisplayText;

    @NotNull
    private HashType authenticationHashType = DEFAULT_AUTHENTICATION_HASH_TYPE;

    @NotNull
    private Integer sessionStatusSocketOpenDuration = DEFAULT_SESSION_STATUS_SOCKET_OPEN_DURATION;

    @NotNull
    private Integer readTimeout = DEFAULT_READ_TIMEOUT;

    @NotNull
    private Integer connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;

    @PostConstruct
    public void init() {
        if (connectionTimeout < sessionStatusSocketOpenDuration) {
            throw new IllegalArgumentException(
                    "Network connection timeout(<" + connectionTimeout + ">) should not be shorter than session status check socket open duration(<" + sessionStatusSocketOpenDuration + ">)");
        }
    }
}
