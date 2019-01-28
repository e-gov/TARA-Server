package ee.ria.sso.oidc;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TaraScope {

    OPENID("openid"),
    IDCARD("idcard"),
    MID("mid"),
    EIDAS("eidas"),
    BANKLINK("banklink"),
    SMARTID("smartid"),
    EIDASONLY("eidasonly");

    private String formalName;

    public static TaraScope getScope(String value) {
        for(TaraScope v : values())
            if(v.formalName.equals(value))
                return v;

        throw new IllegalArgumentException();
    }
}
