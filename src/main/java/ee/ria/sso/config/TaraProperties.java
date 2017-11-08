package ee.ria.sso.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Component
@ConfigurationProperties("tara")
public class TaraProperties {

    private Environment environment = new Environment();

    public Environment getEnvironment() {
        return environment;
    }

    public enum Mode {
        development, production
    }

    public static class Environment {

        private Mode mode = Mode.production;

        public boolean isDevelopment() {
            return Mode.development.equals(this.mode);
        }

        public Mode getMode() {
            return mode;
        }

        public void setMode(Mode mode) {
            this.mode = mode;
        }

    }

}
