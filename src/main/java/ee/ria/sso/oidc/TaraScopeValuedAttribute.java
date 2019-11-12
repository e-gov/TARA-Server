package ee.ria.sso.oidc;

import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;

@Getter
@Builder
public class TaraScopeValuedAttribute implements Serializable {

    private final TaraScopeValuedAttributeName name;
    private final String value;
}
