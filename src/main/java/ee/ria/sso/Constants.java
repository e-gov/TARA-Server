package ee.ria.sso;

import lombok.experimental.UtilityClass;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */
@UtilityClass
public final class Constants {

    public static final String CERTIFICATE_SESSION_ATTRIBUTE = "Client-Certificate";
    public static final String MOBILE_CHALLENGE = "mobileChallenge";
    public static final String MOBILE_SESSION = "mobileSession";
    public static final String AUTH_COUNT = "authCount";
    public static final String ERROR_MESSAGE = "TARA_ERROR_MESSAGE";
    public static final String EVENT_OUTSTANDING = "outstanding";

    public static final String CAS_SERVICE_ATTRIBUTE_NAME = "service";

    public static final String SMART_ID_VERIFICATION_CODE = "smartIdVerificationCode";
    public static final String SMART_ID_AUTHENTICATION_SESSION = "smartIdAuthenticationSession";

    public static final String MESSAGE_KEY_GENERAL_ERROR = "message.error.general";
    public static final String MESSAGE_KEY_SESSION_EXPIRED = "message.error.sessionExpired";
    public static final String MESSAGE_KEY_AUTH_METHOD_RESTRICTED_BY_SCOPE = "message.error.authMethodNotAllowedByScope";

    public static final String MDC_ATTRIBUTE_REQUEST_ID = "requestId";
    public static final String MDC_ATTRIBUTE_SESSION_ID = "sessionId";

    public static final String TARA_OIDC_SESSION_SCOPES = "taraOidcSessionScopes";
    public static final String TARA_OIDC_SESSION_CLIENT_ID = "taraOidcSessionClientId";
    public static final String TARA_OIDC_SESSION_REDIRECT_URI = "taraOidcSessionRedirectUri";
    public static final String TARA_OIDC_SESSION_AUTH_METHODS = "taraOidcSessionAllowedAuthMethods";
    public static final String TARA_OIDC_SESSION_LOA = "taraOidcSessionLoA";

    public static final String TARA_OIDC_DYNAMIC_CLIENT_REGISTRATION_ENDPOINT_ENABLED = "oidc.dynamic-client-registration.enabled";
    public static final String TARA_OIDC_PROFILE_ENDPOINT_ENABLED = "oidc.profile-endpoint.enabled";
    public static final String TARA_OIDC_REVOCATION_ENDPOINT_ENABLED = "oidc.revocation-endpoint.enabled";
    public static final String TARA_OIDC_INTROSPECTION_ENDPOINT_ENABLED = "oidc.introspection-endpoint.enabled";

    public static final String TARA_OIDC_TOKEN_REQUEST_ATTR_ACCESS_TOKEN_ID = "accessTokenId";
    public static final String TARA_OIDC_TOKEN_REQUEST_ATTR_ID_TOKEN = "generatedAndEncodedIdTokenString";
}
