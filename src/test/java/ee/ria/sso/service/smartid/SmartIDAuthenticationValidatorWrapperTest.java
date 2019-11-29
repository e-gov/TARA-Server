package ee.ria.sso.service.smartid;

import ee.ria.sso.config.smartid.TestSmartIDConfiguration;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Arrays;
import java.util.stream.Collectors;

import static ee.ria.sso.service.smartid.SmartIDMockData.mockCompleteSessionStatus;
import static org.junit.Assert.*;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestSmartIDConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class SmartIDAuthenticationValidatorWrapperTest {

    private static final CertificateLevel CERTIFICATE_LEVEL = CertificateLevel.QUALIFIED;

    @Autowired
    private AuthenticationResponseValidator authResponseValidator;
    
    private SmartIDAuthenticationValidatorWrapper validatorWrapper;

    @Before
    public void setup() {
        validatorWrapper = new SmartIDAuthenticationValidatorWrapper(authResponseValidator);
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOK() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);

        AuthenticationHash authHash = SmartIDMockData.mockAuthenticationHash();
        SmartIdAuthenticationResult authenticationResult = validatorWrapper.validateAuthenticationResponse(sessionStatus, authHash, CERTIFICATE_LEVEL);

        assertTrue(authenticationResult.getErrors().isEmpty());
        AuthenticationIdentity authIdentity = authenticationResult.getAuthenticationIdentity();
        assertEquals("EE", authIdentity.getCountry());
        assertEquals("10101010005", authIdentity.getIdentityCode());
        assertEquals("DEMO", authIdentity.getGivenName());
        assertEquals("SMART-ID", authIdentity.getSurName());
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultUserRefused() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.USER_REFUSED);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.USER_REFUSED_AUTHENTICATION,
                "User refused authentication"
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultTimeout() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.TIMEOUT);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.SESSION_TIMED_OUT,
                "Authentication session timed out"
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultDocumentUnusable() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.DOCUMENT_UNUSABLE);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.USER_DOCUMENT_UNUSABLE,
                "User document is unusable"
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultUnknown() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        sessionStatus.getResult().setEndResult("UNKNOWN_SESSION_END_RESULT");
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                IllegalStateException.class,
                SmartIDErrorMessage.GENERAL,
                "Unknown authentication session end result <UNKNOWN_SESSION_END_RESULT>"
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOk_certMissing() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        sessionStatus.getCert().setValue(null);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                TechnicalErrorException.class,
                SmartIDErrorMessage.GENERAL,
                "Certificate is not present in the authentication response"
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOk_invalidSignature() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        sessionStatus.getSignature().setValue(SmartIDMockData.INVALID_SIGNATURE_IN_BASE64);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, AuthenticationHash.generateRandomHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.GENERAL,
                SmartIdAuthenticationResult.Error.SIGNATURE_VERIFICATION_FAILURE.getMessage()
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOk_certLevelMismatch() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        sessionStatus.getCert().setCertificateLevel(CertificateLevel.ADVANCED.name());
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, SmartIDMockData.mockAuthenticationHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.GENERAL,
                SmartIdAuthenticationResult.Error.CERTIFICATE_LEVEL_MISMATCH.getMessage()
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOk_certificateUntrusted() {
        AuthenticationResponseValidator authResponseValidator = new AuthenticationResponseValidator();
        authResponseValidator.clearTrustedCACertificates();
        SmartIDAuthenticationValidatorWrapper validator = new SmartIDAuthenticationValidatorWrapper(authResponseValidator);

        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        expectException(
                () -> validator.validateAuthenticationResponse(sessionStatus, SmartIDMockData.mockAuthenticationHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.GENERAL,
                SmartIdAuthenticationResult.Error.CERTIFICATE_NOT_TRUSTED.getMessage()
        );
    }

    @Test
    public void getAuthenticationSessionStatus_sessionComplete_endResultOk_multipleFailures() {
        SessionStatus sessionStatus = mockCompleteSessionStatus(SessionEndResult.OK);
        sessionStatus.getCert().setValue(SmartIDMockData.EXPIRED_AUTH_CERTIFICATE);
        expectException(
                () -> validatorWrapper.validateAuthenticationResponse(sessionStatus, SmartIDMockData.mockAuthenticationHash(), CERTIFICATE_LEVEL),
                SessionValidationException.class,
                SmartIDErrorMessage.GENERAL,
                SmartIdAuthenticationResult.Error.SIGNATURE_VERIFICATION_FAILURE.getMessage(),
                SmartIdAuthenticationResult.Error.CERTIFICATE_EXPIRED.getMessage(),
                SmartIdAuthenticationResult.Error.CERTIFICATE_NOT_TRUSTED.getMessage()
        );
    }

    private void expectException(Runnable processToThrowException, Class<? extends Exception> exceptionType, String errorMessageKey, String... errorMessage) {
        try {
            processToThrowException.run();
        } catch (Exception e) {
            if (!exceptionType.isInstance(e)) {
                fail("Invalid exception caught! Is <" + e.getClass() + ">, but expected to be <" + exceptionType + ">");
            }
            if (e instanceof SessionValidationException) {
                assertEquals(errorMessageKey, ((SessionValidationException)e).getErrorMessageKey());
            }
            assertEquals(Arrays.asList(errorMessage).stream().collect(Collectors.joining(",")), e.getMessage());
        }
    }
}
