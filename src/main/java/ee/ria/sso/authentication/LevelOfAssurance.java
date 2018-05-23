package ee.ria.sso.authentication;

import java.util.HashMap;
import java.util.Map;

public enum LevelOfAssurance {

    LOW("http://eidas.europa.eu/LoA/low", "low"),
    SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial", "substantial"),
    HIGH("http://eidas.europa.eu/LoA/high", "high");

    private final String formalName;
    private final String acrName;

    LevelOfAssurance(String formalName, String acrName) {
        this.formalName = formalName;
        this.acrName = acrName;
    }

    public String getFormalName() {
        return this.formalName;
    }

    public String getAcrName() {
        return this.acrName;
    }

    private static final Map<String, LevelOfAssurance> map;

    static {
        map = new HashMap<String, LevelOfAssurance>();
        for (LevelOfAssurance loa : LevelOfAssurance.values()) {
            map.put(loa.formalName, loa);
        }
    }

    public static LevelOfAssurance findByFormalName(String formalName) {
        return map.get(formalName);
    }
}
