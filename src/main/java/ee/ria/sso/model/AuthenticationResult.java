package ee.ria.sso.model;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationResult {

    private String levelOfAssurance;

    private Map<String, String> attributes = new HashMap<>();

    private Map<String, String> attributesTransliterated = new HashMap<>();

    public String getLevelOfAssurance() {
        return levelOfAssurance;
    }

    public void setLevelOfAssurance(String levelOfAssurance) {
        this.levelOfAssurance = levelOfAssurance;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public Map<String, String> getAttributesTransliterated() {
        return attributesTransliterated;
    }

    public void setAttributesTransliterated(Map<String, String> attributesTransliterated) {
        this.attributesTransliterated = attributesTransliterated;
    }
}
