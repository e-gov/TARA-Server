package ee.ria.sso.authentication;

import com.nortal.banklink.link.Bank;

public enum BankEnum {
    SWEDBANK(Bank.SWEDBANK),
    SEB(Bank.SEB),
    DANSKE(Bank.DANSKE),
    COOP(Bank.KRED),
    LUMINOR(Bank.NORDEA),
    LHV(Bank.LHV),
    ;

    private BankEnum(Bank authLinkBank) {
        this.authLinkBank = authLinkBank;
    }

    private Bank authLinkBank;

    public String getName() {
        return name().toLowerCase();
    }
    public Bank getAuthLinkBank() {
        return authLinkBank;
    }
}