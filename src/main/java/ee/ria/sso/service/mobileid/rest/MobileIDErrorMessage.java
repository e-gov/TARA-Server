package ee.ria.sso.service.mobileid.rest;

public class MobileIDErrorMessage {

    private static final String MESSAGE_PREFIX = "message.mid-rest.error.";

    public static final String TECHNICAL = MESSAGE_PREFIX + "internal-error";
    public static final String INVALID_IDENTITY_CODE = MESSAGE_PREFIX + "invalid-identity-code";
    public static final String INVALID_MOBILE_NUMBER = MESSAGE_PREFIX + "invalid-phone-number";
    public static final String TRANSACTION_EXPIRED = MESSAGE_PREFIX + "expired-transaction";
    public static final String USER_CANCELLED = MESSAGE_PREFIX + "user-cancel";
    public static final String PHONE_ABSENT = MESSAGE_PREFIX + "phone-absent";
    public static final String SIM_ERROR = MESSAGE_PREFIX + "sim-error";
    public static final String NOT_MID_CLIENT = MESSAGE_PREFIX + "not-mid-client";
    public static final String SIGNATURE_HASH_MISMATCH = MESSAGE_PREFIX + "signature-hash-mismatch";
    public static final String DELIVERY_ERROR = MESSAGE_PREFIX + "delivery-error";
}
