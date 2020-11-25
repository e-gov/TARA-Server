package ee.ria.sso.config.cas;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties("cas")
public class CasConfigProperties {

    @NotNull
    @Value("${cas.server.name}")
    private String serverName;
}
