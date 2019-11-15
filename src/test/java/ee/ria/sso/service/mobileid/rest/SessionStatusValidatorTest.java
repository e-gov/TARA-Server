package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

public class SessionStatusValidatorTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void sessionResultOK() {
        SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("OK"));
    }

    @Test
    public void unhandledSessionResult_exceptionThrown() {
        expectedException.expect(MidInternalErrorException.class);
        SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("UNHANDLED_UNKNOWN_RESULT_CODE"));
    }

    @Test
    public void sessionResultTimeout_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("TIMEOUT"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.TRANSACTION_EXPIRED, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultExpiredTransaction_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("TIMEOUT"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.TRANSACTION_EXPIRED, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultNotMidClient_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("NOT_MID_CLIENT"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.NOT_MID_CLIENT, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultUserCancelled_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("USER_CANCELLED"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.USER_CANCELLED, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultSignatureHashMismatch_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("SIGNATURE_HASH_MISMATCH"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.SIGNATURE_HASH_MISMATCH, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultPhoneAbsent_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("PHONE_ABSENT"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.PHONE_ABSENT, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultSimError_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("SIM_ERROR"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.SIM_ERROR, e.getErrorMessageKey());
        }
    }

    @Test
    public void sessionResultDeliveryError_exceptionThrown() {
        try {
            SessionStatusValidator.validateAuthenticationResult(mockSessionStatus("DELIVERY_ERROR"));
        } catch (UserAuthenticationFailedException e) {
            assertEquals(MobileIDErrorMessage.DELIVERY_ERROR, e.getErrorMessageKey());
        }
    }

    @Test
    public void nothingValidatedIfResultIsNull() {
        SessionStatusValidator.validateAuthenticationResult(mockSessionStatus(null));
    }

    private MidSessionStatus mockSessionStatus(String resultCode) {
        MidSessionStatus midSessionStatus = new MidSessionStatus();
        midSessionStatus.setState("COMPLETE");
        midSessionStatus.setResult(resultCode);
        midSessionStatus.setCert("cert");
        return midSessionStatus;
    }
}
