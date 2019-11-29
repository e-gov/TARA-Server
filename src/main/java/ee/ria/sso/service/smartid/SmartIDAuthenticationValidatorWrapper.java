package ee.ria.sso.service.smartid;

import ee.sk.smartid.*;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.EnumUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@ConditionalOnProperty("smart-id.enabled")
@Component
@RequiredArgsConstructor
public class SmartIDAuthenticationValidatorWrapper {

    private final AuthenticationResponseValidator validator;

    public SmartIdAuthenticationResult validateAuthenticationResponse(SessionStatus sessionStatus, AuthenticationHash authHash, CertificateLevel certificateLevel) {
        validateSessionEndResult(sessionStatus.getResult().getEndResult());
        SmartIdAuthenticationResponse authResponse = formAuthenticationResponse(sessionStatus, authHash, certificateLevel);
        SmartIdAuthenticationResult validationResult = validator.validate(authResponse);
        if (!validationResult.isValid()) {
            List<String> errors = validationResult.getErrors();
            String commaSeparatedErrors = errors.stream().collect(Collectors.joining(","));
            throw new SessionValidationException(commaSeparatedErrors, SmartIDErrorMessage.GENERAL);
        }
        return validationResult;
    }

    private void validateSessionEndResult(String sessionEndResult) {
        SessionEndResult endResult = EnumUtils.getEnum(SessionEndResult.class, sessionEndResult);
        if (endResult == null) {
            throw new IllegalStateException("Unknown authentication session end result <" + sessionEndResult + ">");
        }

        switch (endResult) {
            case OK:
                return;
            case USER_REFUSED :
                throw new SessionValidationException("User refused authentication", SmartIDErrorMessage.USER_REFUSED_AUTHENTICATION);
            case TIMEOUT:
                throw new SessionValidationException("Authentication session timed out",SmartIDErrorMessage.SESSION_TIMED_OUT);
            case DOCUMENT_UNUSABLE:
                throw new SessionValidationException("User document is unusable", SmartIDErrorMessage.USER_DOCUMENT_UNUSABLE);
            default:
                throw new IllegalStateException("Unhandled authentication session end result <" + endResult + ">");
        }
    }

    private SmartIdAuthenticationResponse formAuthenticationResponse(SessionStatus sessionStatus, AuthenticationHash authHash, CertificateLevel certificateLevel) {
        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate certificate = sessionStatus.getCert();

        SmartIdAuthenticationResponse authenticationResponse = new SmartIdAuthenticationResponse();
        authenticationResponse.setEndResult(sessionResult.getEndResult());
        authenticationResponse.setSignedHashInBase64(authHash.getHashInBase64());
        authenticationResponse.setHashType(authHash.getHashType());
        authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());
        authenticationResponse.setAlgorithmName(sessionSignature.getAlgorithm());
        authenticationResponse.setRequestedCertificateLevel(certificateLevel.name());
        if (certificate.getValue() != null) {
            authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
        }
        authenticationResponse.setCertificateLevel(certificate.getCertificateLevel());
        return authenticationResponse;
    }
}
