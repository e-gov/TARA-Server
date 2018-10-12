package ee.ria.sso.authentication;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
@Getter
@AllArgsConstructor
public enum AuthenticationType {

    Default("", ""),
    IDCard("idcard", "id-card"),
    MobileID("mID", "mobile-id"),
    eIDAS("eIDAS", "eidas"),
    BankLink("banklink", "banklinks"),
    SmartID("smartid", "smart-id");

    private final String amrName;
    private final String propertyName;

}
