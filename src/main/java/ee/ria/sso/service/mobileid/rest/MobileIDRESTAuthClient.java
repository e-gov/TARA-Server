package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.manager.ManagerService;
import ee.ria.sso.service.mobileid.AuthenticationIdentity;
import ee.ria.sso.service.mobileid.MobileIDAuthenticationClient;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidAuthenticationIdentity;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidAuthenticationResult;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidLanguage;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.exception.MidMissingOrInvalidParameterException;
import ee.sk.mid.exception.MidSessionNotFoundException;
import ee.sk.mid.exception.MidUnauthorizedException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.request.MidSessionStatusRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.io.IOException;
import java.security.cert.CertificateException;

@ConditionalOnProperty("mobile-id.enabled")
@Slf4j
public class MobileIDRESTAuthClient implements MobileIDAuthenticationClient<MobileIDRESTSession, MobileIDRESTSessionStatus> {

    private final MobileIDConfigurationProvider confProvider;
    private final MidClient client;
    private final MidAuthenticationResponseValidator validator = new MidAuthenticationResponseValidator();

    public MobileIDRESTAuthClient(MobileIDConfigurationProvider confProvider, MidClient client) throws IOException, CertificateException {
        this.confProvider = confProvider;
        this.client = client;
        validator.addTrustedCACertificate(FileUtils.getFile(MobileIDRESTAuthClient.class.getResource("/trusted_certificates/TEST_of_ESTEID-SK_2015.pem.crt").getFile()));
    }

    @Override
    public MobileIDRESTSession initAuthentication(String personalCode, String countryCode, String phoneNumber) {
        MidAuthenticationHashToSign authenticationHash = MidAuthenticationHashToSign.generateRandomHashOfType(confProvider.getAuthenticationHashType());



        MidAuthenticationRequest request = MidAuthenticationRequest.newBuilder()
                .withPhoneNumber(phoneNumber)
                .withNationalIdentityNumber(personalCode)
                .withHashToSign(authenticationHash)
                .withLanguage(MidLanguage.valueOf(confProvider.getLanguage()))
                .withDisplayText(managerService.getServiceShortName().orElse(confProvider.getMessageToDisplay()))
                .withDisplayTextFormat(confProvider.getMessageToDisplayEncoding())
                .build();

        MidAuthenticationResponse response = authenticate(request);

        return MobileIDRESTSession.builder()
                .sessionId(response.getSessionID())
                .verificationCode(authenticationHash.calculateVerificationCode())
                .authenticationHash(authenticationHash)
                .build();
    }

    @Override
    public MobileIDRESTSessionStatus pollAuthenticationSessionStatus(MobileIDRESTSession session) {
        MidSessionStatusRequest request = new MidSessionStatusRequest(session.getSessionId(), confProvider.getSessionStatusSocketOpenDuration());
        MidSessionStatus sessionStatus = pollSessionStatus(request);
        SessionStatusValidator.validateAuthenticationResult(sessionStatus);

        return MobileIDRESTSessionStatus.builder()
                .authenticationComplete(isAuthenticationComplete(sessionStatus))
                .wrappedSessionStatus(sessionStatus)
                .build();
    }

    @Override
    public AuthenticationIdentity getAuthenticationIdentity(MobileIDRESTSession session, MobileIDRESTSessionStatus sessionStatus) {
        MidAuthentication authentication = createMobileIdAuthentication(sessionStatus.getWrappedSessionStatus(), session.getAuthenticationHash());
        MidAuthenticationIdentity authenticationIdentity = validateAndGetAuthIdentity(authentication);

        return AuthenticationIdentity.builder()
                .identityCode(authenticationIdentity.getIdentityCode())
                .givenName(authenticationIdentity.getGivenName())
                .surname(authenticationIdentity.getSurName())
                .build();
    }

    private boolean isAuthenticationComplete(MidSessionStatus sessionStatus) {
        String result = sessionStatus.getResult();
        return sessionStatus.getState().equalsIgnoreCase("COMPLETE") && result != null
                && result.equalsIgnoreCase("OK");
    }

    private MidAuthenticationResponse authenticate(MidAuthenticationRequest request) {
        try {
            return client.getMobileIdConnector().authenticate(request);
        } catch (MidInternalErrorException e) {
            throw new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "MID service returned internal error that cannot be handled locally", e);
        } catch (MidMissingOrInvalidParameterException | MidUnauthorizedException e) {
            throw new IllegalStateException("Integrator-side error with MID integration or configuration", e);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error occurred during authentication initiation", e);
        }
    }

    private MidSessionStatus pollSessionStatus(MidSessionStatusRequest request) {
        try {
            return client.getMobileIdConnector().getAuthenticationSessionStatus(request);
        } catch (MidInternalErrorException e) {
            throw new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "MID service returned internal error that cannot be handled locally", e);
        } catch (MidSessionNotFoundException | MidMissingOrInvalidParameterException | MidUnauthorizedException e) {
            throw new IllegalStateException("Integrator-side error with MID integration or configuration", e);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error occurred during authentication session status polling", e);
        }
    }

    private MidAuthentication createMobileIdAuthentication(MidSessionStatus sessionStatus, MidAuthenticationHashToSign authenticationHash) {
        try {
            return client.createMobileIdAuthentication(sessionStatus, authenticationHash);
        } catch (MidInternalErrorException e) {
            throw new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "MID service returned internal error that cannot be handled locally", e);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error occurred during creating Mobile-ID authentication", e);
        }
    }

    private MidAuthenticationIdentity validateAndGetAuthIdentity(MidAuthentication authentication) {
        MidAuthenticationResult authResult = validateAuthentication(authentication);
        if (!authResult.isValid() || !authResult.getErrors().isEmpty()) {
            throw new AuthenticationValidationException("Authentication result validation failed with: " + authResult.getErrors());
        }

        return authResult.getAuthenticationIdentity();
    }

    private MidAuthenticationResult validateAuthentication(MidAuthentication authentication) {
        try {
            return validator.validate(authentication);
        } catch (MidInternalErrorException e) {
            throw new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "Authentication validation failed", e);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error occurred during authentication validation", e);
        }
    }
}
