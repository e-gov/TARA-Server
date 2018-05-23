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

    private static final Map<String, LevelOfAssurance> formalNameMap;
    private static final Map<String, LevelOfAssurance> acrNameMap;

    static {
        formalNameMap = new HashMap<String, LevelOfAssurance>();
        acrNameMap = new HashMap<String, LevelOfAssurance>();

        for (LevelOfAssurance loa : LevelOfAssurance.values()) {
            formalNameMap.put(loa.formalName, loa);
            acrNameMap.put(loa.acrName, loa);
        }
    }

    public static LevelOfAssurance findByFormalName(String formalName) {
        return formalNameMap.get(formalName);
    }

    public static LevelOfAssurance findByAcrName(String acrName) {
        return acrNameMap.get(acrName);
    }
}
