package ee.ria.sso.config.cas;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotNull;

@Data
@ConfigurationProperties("cas")
public class CasConfigProperties {

    @NotNull
    @Value("${cas.server.name}")
    private String serverName;
}
