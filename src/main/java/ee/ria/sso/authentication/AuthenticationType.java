package ee.ria.sso.authentication;

import ee.ria.sso.oidc.TaraScope;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthenticationType {

    Default("", "", null),
    IDCard("idcard", "id-card", TaraScope.IDCARD),
    MobileID("mID", "mobile-id", TaraScope.MID),
    eIDAS("eIDAS", "eidas", TaraScope.EIDAS),
    BankLink("banklink", "banklinks", TaraScope.BANKLINK),
    SmartID("smartid", "smart-id", TaraScope.SMARTID);

    private final String amrName;
    private final String propertyName;
    private final TaraScope scope;
}
