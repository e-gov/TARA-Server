package ee.ria.sso.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

@Getter
@AllArgsConstructor
public enum CspDirective {

    CHILD_SRC(Type.FETCH, Value.NEEDED, "child-src"),
    CONNECT_SRC(Type.FETCH, Value.NEEDED, "connect-src"),
    DEFAULT_SRC(Type.FETCH, Value.NEEDED, "default-src"),
    FONT_SRC(Type.FETCH, Value.NEEDED, "font-src"),
    FRAME_SRC(Type.FETCH, Value.NEEDED, "frame-src"),
    IMG_SRC(Type.FETCH, Value.NEEDED, "img-src"),
    MANIFEST_SRC(Type.FETCH, Value.NEEDED, "manifest-src"),
    MEDIA_SRC(Type.FETCH, Value.NEEDED, "media-src"),
    OBJECT_SRC(Type.FETCH, Value.NEEDED, "object-src"),
    SCRIPT_SRC(Type.FETCH, Value.NEEDED, "script-src"),
    STYLE_SRC(Type.FETCH, Value.NEEDED, "style-src"),
    WORKER_SRC(Type.FETCH, Value.NEEDED, "worker-src"),

    BASE_URI(Type.DOCUMENT, Value.NEEDED, "base-uri"),
    PLUGIN_TYPES(Type.DOCUMENT, Value.NEEDED, "plugin-types"),
    SANDBOX(Type.DOCUMENT, Value.OPTIONAL, "sandbox"),
    DISOWN_OPENER(Type.DOCUMENT, Value.NONE, "disown-opener"),

    FORM_ACTION(Type.NAVIGATION, Value.NEEDED, "form-action"),
    FRAME_ANCESTORS(Type.NAVIGATION, Value.NEEDED, "frame-ancestors"),

    REPORT_URI(Type.REPORTING, Value.NEEDED, "report-uri"),
    REPORT_TO(Type.REPORTING, Value.NEEDED, "report-to"),

    BLOCK_ALL_MIXED_CONTENT(Type.OTHER, Value.NONE, "block-all-mixed-content"),
    UPGRADE_INSECURE_REQUESTS(Type.OTHER, Value.NONE, "upgrade-insecure-requests"),
    REQUIRE_SRI_FOR(Type.OTHER, Value.NEEDED, "require-sri-for");

    public enum Type {
        FETCH, DOCUMENT, NAVIGATION, REPORTING, OTHER;
    }

    public enum Value {
        NEEDED, OPTIONAL, NONE;
    }

    @NonNull
    final Type type;
    @NonNull
    final Value value;
    @NonNull
    final String cspName;

    public void validateValue(final String value) {
        switch (this.value) {

            case NONE:
                if (StringUtils.isNotEmpty(value))
                    throw new IllegalArgumentException(String.format(
                            "CSP directive %s must not have a value",
                            this.cspName
                    ));
                return;

            case OPTIONAL:
                if (StringUtils.isBlank(value))
                    return;

            case NEEDED:
                if (StringUtils.isBlank(value))
                    throw new IllegalArgumentException(String.format(
                            "CSP directive %s must have at least one value",
                            this.cspName
                    ));
                break;

        }

        if (value.indexOf(';') >= 0)
            throw new IllegalArgumentException("A CSP directive value must not contain ';'");
    }

}
