package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.sk.mid.exception.MidException;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.rest.dao.MidSessionStatus;

final class SessionStatusValidator {

    static void validateAuthenticationResult(MidSessionStatus sessionStatus) {
        String authenticationResult = sessionStatus.getResult();
        if (authenticationResult != null) {
            validateAuthenticationResult(authenticationResult);
        }
    }

    private static void validateAuthenticationResult(String authenticationResult) throws MidException {
        switch (authenticationResult) {
            case "OK":
                return;
            case "TIMEOUT":
            case "EXPIRED_TRANSACTION":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.TRANSACTION_EXPIRED, "User didn't enter PIN code or communication error.");
            case "NOT_MID_CLIENT":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.NOT_MID_CLIENT, "User is not a MID client or user's certificates are revoked.");
            case "USER_CANCELLED":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.USER_CANCELLED, "User cancelled operation from his/her phone.");
            case "SIGNATURE_HASH_MISMATCH":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.SIGNATURE_HASH_MISMATCH, "Mobile-ID configuration on user's SIM card differs from what is configured on service provider's side. User needs to contact his/her mobile operator.");
            case "PHONE_ABSENT":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.PHONE_ABSENT, "Unable to reach phone/SIM card. User needs to check if phone has coverage.");
            case "SIM_ERROR":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.SIM_ERROR, "Error communicating with the SIM card.");
            case "DELIVERY_ERROR":
                throw new UserAuthenticationFailedException(MobileIDErrorMessage.DELIVERY_ERROR, "Error communicating with the phone/SIM card.");
            default:
                throw new MidInternalErrorException("MID returned unexpected error code '" + authenticationResult + "'");
        }
    }
}
