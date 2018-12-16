package ee.ria.sso;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public final class Constants {

    public static final String CERTIFICATE_SESSION_ATTRIBUTE = "Client-Certificate";
    public static final String MOBILE_CHALLENGE = "mobileChallenge";
    public static final String MOBILE_SESSION = "mobileSession";
    public static final String AUTH_COUNT = "authCount";
    public static final String ERROR_MESSAGE = "TARA_ERROR_MESSAGE";
    public static final String CREDENTIAL = "credential";

    public static final String CAS_SERVICE_ATTRIBUTE_NAME = "service";

    public static final String SMART_ID_VERIFICATION_CODE = "smartIdVerificationCode";
    public static final String SMART_ID_AUTHENTICATION_SESSION = "smartIdAuthenticationSession";

    public static final String MESSAGE_KEY_GENERAL_ERROR = "message.error.general";
    public static final String MESSAGE_KEY_SESSION_EXPIRED = "message.error.sessionExpired";

    public static final String MDC_ATTRIBUTE_REQUEST_ID = "requestId";
    public static final String MDC_ATTRIBUTE_SESSION_ID = "sessionId";

    public static final String TARA_OIDC_SESSION_SCOPES = "taraOidcSessionScopes";
    public static final String TARA_OIDC_SESSION_CLIENT_ID = "taraOidcSessionClientId";
    public static final String TARA_OIDC_SESSION_REDIRECT_URI = "taraOidcSessionRedirectUri";
    public static final String TARA_OIDC_SESSION_AUTH_METHODS = "taraOidcSessionAllowedAuthMethods";
    public static final String TARA_OIDC_SESSION_LoA = "taraOidcSessionLoA";

}
