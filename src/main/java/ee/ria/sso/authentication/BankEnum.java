package ee.ria.sso.authentication;

import com.nortal.banklink.link.Bank;

import java.util.HashMap;
import java.util.Map;


public enum BankEnum {
    SWEDBANK("bank.swedbank.sender.id", "bank.swedbank.rec.id", "bank.swedbank.url", Bank.SWEDBANK),

    SEB("bank.seb.sender.id", "bank.seb.rec.id", "bank.seb.url", Bank.SEB),
    DANSKE("bank.danske.sender.id", "bank.danske.rec.id", "bank.danske.url", Bank.DANSKE),

    COOP("bank.coop.sender.id", "bank.coop.rec.id", "bank.coop.url", Bank.KRED),
    LUMINOR("bank.luminor.sender.id", "bank.luminor.rec.id", "bank.luminor.url", Bank.NORDEA),
    LHV("bank.lhv.sender.id", "bank.lhv.rec.id", "bank.lhv.url", Bank.LHV),
    ;

    private BankEnum(String vkSenderIdCode, String vkRecIdCode, String urlCode, Bank authLinkBank) {
        this.vkSenderIdCode = vkSenderIdCode;
        this.vkRecIdCode = vkRecIdCode;
        this.urlCode = urlCode;
        this.authLinkBank = authLinkBank;
    }

    private String vkSenderIdCode;
    private String vkRecIdCode;
    private String urlCode;
    private Bank authLinkBank;

    public String getName() {
        return name().toLowerCase();
    }

    public String getVkSenderIdCode() {
        return vkSenderIdCode;
    }

    public String getVkRecIdCode() {
        return vkRecIdCode;
    }

    public String getUrlCode() {
        return urlCode;
    }

    public Bank getAuthLinkBank() {
        return authLinkBank;
    }


}