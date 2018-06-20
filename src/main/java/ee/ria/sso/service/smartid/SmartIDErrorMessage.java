package ee.ria.sso.service.smartid;

class SmartIDErrorMessage {

    private static final String MESSAGE_PREFIX = "message.smartId.error.";

    public static final String GENERAL = MESSAGE_PREFIX + "general";
    public static final String PERSON_IDENTIFIER_MISSING = MESSAGE_PREFIX + "missingPersonIdentifier";
    public static final String INVALID_PERSON_IDENTIFIER = MESSAGE_PREFIX + "invalidPersonIdentifier";
    public static final String USER_ACCOUNT_NOT_FOUND = MESSAGE_PREFIX + "userAccountNotFound";
    public static final String REQUEST_FORBIDDEN = MESSAGE_PREFIX + "requestForbidden";
    public static final String USER_REFUSED_AUTHENTICATION = MESSAGE_PREFIX + "userRefusedAuth";
    public static final String SESSION_TIMED_OUT = MESSAGE_PREFIX + "sessionTimedOut";
    public static final String USER_DOCUMENT_UNUSABLE = MESSAGE_PREFIX + "userDocumentUnusable";
    public static final String SESSION_NOT_FOUND = MESSAGE_PREFIX + "sessionNotFound";
    public static final String USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT = MESSAGE_PREFIX + "userDoesNotHaveQueryMatchingAccount";
    public static final String SMART_ID_SYSTEM_UNDER_MAINTENANCE = "smartIdSystemUnderMaintenance";
    public static final String UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE = "instructionsInUserDeviceOrPortal";
}
