package ee.ria.sso.validators;

public enum TaraScope {

    OPENID("openid", true),
    EIDASONLY("eidasonly", false);

    private String formalName;
    private boolean required;

    TaraScope(String formalName, boolean required) {
        this.formalName = formalName;
        this.required = required;
    }

    public String getFormalName() {
        return this.formalName;
    }

    public boolean isRequired() {
        return this.required;
    }
}
