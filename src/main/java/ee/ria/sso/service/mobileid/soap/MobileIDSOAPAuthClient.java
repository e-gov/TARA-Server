package ee.ria.sso.service.mobileid.soap;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.AuthenticationException.Code;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.mobileid.AuthenticationIdentity;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.codeborne.security.AuthenticationException.Code.AUTHENTICATION_ERROR;
import static com.codeborne.security.AuthenticationException.Code.CERTIFICATE_REVOKED;
import static com.codeborne.security.AuthenticationException.Code.EXPIRED_TRANSACTION;
import static com.codeborne.security.AuthenticationException.Code.INTERNAL_ERROR;
import static com.codeborne.security.AuthenticationException.Code.MID_NOT_READY;
import static com.codeborne.security.AuthenticationException.Code.NOT_ACTIVATED;
import static com.codeborne.security.AuthenticationException.Code.NOT_VALID;
import static com.codeborne.security.AuthenticationException.Code.NO_AGREEMENT;
import static com.codeborne.security.AuthenticationException.Code.PHONE_ABSENT;
import static com.codeborne.security.AuthenticationException.Code.SENDING_ERROR;
import static com.codeborne.security.AuthenticationException.Code.SERVICE_ERROR;
import static com.codeborne.security.AuthenticationException.Code.SIM_ERROR;
import static com.codeborne.security.AuthenticationException.Code.UNABLE_TO_TEST_USER_CERTIFICATE;
import static com.codeborne.security.AuthenticationException.Code.USER_CANCEL;
import static com.codeborne.security.AuthenticationException.Code.USER_CERTIFICATE_MISSING;
import static com.codeborne.security.AuthenticationException.Code.USER_PHONE_ERROR;

/**
 * Old DDS based Mobile-ID authentication logic refactored out from MobileIDAuthenticationService.
 */
@ConditionalOnProperty("mobile-id.enabled")
public class MobileIDSOAPAuthClient implements MobileIDAuthenticationClient<MobileIDSOAPSession, MobileIDSOAPSessionStatus> {

    private static final List<Code> AUTH_INIT_USER_ERROR_CODES = Arrays.asList(USER_PHONE_ERROR, NO_AGREEMENT, CERTIFICATE_REVOKED, NOT_ACTIVATED, NOT_VALID);
    private static final List<Code> AUTH_INIT_TECHNICAL_ERROR_CODES = Arrays.asList(AUTHENTICATION_ERROR, USER_CERTIFICATE_MISSING, UNABLE_TO_TEST_USER_CERTIFICATE);
    private static final List<Code> AUTH_STATUS_CHECK_ERROR_CODES = Arrays.asList(EXPIRED_TRANSACTION, USER_CANCEL, MID_NOT_READY, PHONE_ABSENT, SENDING_ERROR, SIM_ERROR, NOT_VALID);

    private final MobileIDAuthenticatorWrapper authenticator;

    public MobileIDSOAPAuthClient(MobileIDAuthenticatorWrapper authenticator) {
        super();
        this.authenticator = authenticator;
    }

    @Override
    public MobileIDSOAPSession initAuthentication(String personalCode, String countryCode, String phoneNumber) {
        try {
            return MobileIDSOAPSession.builder()
                    .wrappedSession(authenticator.startLogin(personalCode, countryCode, phoneNumber))
                    .build();
        } catch (AuthenticationException e) {
            return handleAuthenticationInitiationException(e);
        }
    }

    @Override
    public MobileIDSOAPSessionStatus pollAuthenticationSessionStatus(MobileIDSOAPSession session) {
        try {
            return MobileIDSOAPSessionStatus.builder()
                    .authenticationComplete(authenticator.isLoginComplete(session.getWrappedSession()))
                    .build();
        } catch (AuthenticationException e) {
            return handleAuthenticateStatusCheckException(e);
        }
    }

    @Override
    public AuthenticationIdentity getAuthenticationIdentity(MobileIDSOAPSession session, MobileIDSOAPSessionStatus sessionStatus) {
        return AuthenticationIdentity.builder()
                .identityCode(session.getWrappedSession().personalCode)
                .givenName(session.getWrappedSession().firstName)
                .surname(session.getWrappedSession().lastName)
                .build();
    }

    private MobileIDSOAPSession handleAuthenticationInitiationException(AuthenticationException e) {
        if (AUTH_INIT_USER_ERROR_CODES.contains(e.getCode())) {
            String messageKey = String.format("message.mid.%s", e.getCode().name().toLowerCase().replace("_", ""));
            String errorMessage = String.format("User authentication failed! DDS MobileAuthenticate returned an error (code: %s)", e.getCode());
            throw new UserAuthenticationFailedException(messageKey, errorMessage, e);
        } else if (AUTH_INIT_TECHNICAL_ERROR_CODES.contains(e.getCode())
                || (e.getCode() == SERVICE_ERROR && e.getCause() instanceof IOException)) {
            String errorMessage = String.format("Technical problems with DDS! DDS MobileAuthenticate returned an error (code: %s)", e.getCode());
            throw new ExternalServiceHasFailedException("message.mid.error", errorMessage, e);
        } else {
            String errorMessage = String.format("Unexpected error returned by DDS MobileAuthenticate (code: %s)!", e.getCode());
            throw new IllegalStateException(errorMessage, e);
        }
    }

    private MobileIDSOAPSessionStatus handleAuthenticateStatusCheckException(AuthenticationException e) {
        if (AUTH_STATUS_CHECK_ERROR_CODES.contains(e.getCode())) {
            String messageKey = String.format("message.mid.%s", e.getCode().name().toLowerCase().replace("_", ""));
            String errorMessage = String.format("User authentication failed! DDS GetMobileAuthenticateStatus returned an error (code: %s)", e.getCode());
            throw new UserAuthenticationFailedException(messageKey, errorMessage, e);
        } else if (INTERNAL_ERROR == e.getCode()
                || e.getCode() == SERVICE_ERROR && e.getCause() instanceof IOException) {
            String errorMessage = String.format("Technical problems with DDS! DDS GetMobileAuthenticateStatus returned an error (code: %s)", e.getCode());
            throw new ExternalServiceHasFailedException("message.mid.error", errorMessage, e);
        } else {
            String errorMessage = String.format("Unexpected error returned by DDS GetMobileAuthenticateStatus (code: %s)", e.getCode());
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
