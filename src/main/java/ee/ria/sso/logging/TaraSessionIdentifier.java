package ee.ria.sso.logging;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

@Getter
@AllArgsConstructor
public class TaraSessionIdentifier {

    public static final String TARA_SESSION_IDENTIFIER_KEY = TaraSessionIdentifier.class.getName();

    @NonNull
    private final String sessionId;

}
