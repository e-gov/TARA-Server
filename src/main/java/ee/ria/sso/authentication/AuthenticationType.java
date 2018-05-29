package ee.ria.sso.authentication;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum AuthenticationType {

    Default(""), IDCard("idcard"), MobileID("mID"), eIDAS("eIDAS"), BankLink("banklink");

    private final String amrName;

    AuthenticationType(String amrName) {
        this.amrName = amrName;
    }

    public String getAmrName() {
        return this.amrName;
    }
}
