package ee.ria.sso.oidc;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TaraScopeValuedAttributeName {

    EIDAS_COUNTRY("eidas:country");

    private final String formalName;

    public static TaraScopeValuedAttributeName getByFormalName(String formalName) {
        for(TaraScopeValuedAttributeName attributeName : values())
            if(attributeName.formalName.equals(formalName))
                return attributeName;

        throw new IllegalArgumentException("Invalid tara scope valued attribute name '" + formalName + "'");
    }
}
