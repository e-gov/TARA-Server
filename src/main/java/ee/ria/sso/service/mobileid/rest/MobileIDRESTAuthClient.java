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
import ee.sk.mid.MidDisplayTextFormat;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ConditionalOnProperty("mobile-id.enabled")
@Slf4j
public class MobileIDRESTAuthClient implements MobileIDAuthenticationClient<MobileIDRESTSession, MobileIDRESTSessionStatus> {

    private static final MidDisplayTextFormat DISPLAY_ENCODING = MidDisplayTextFormat.GSM7;
    private static final MidDisplayTextFormat SPECIAL_CHARACTERS_DISPLAY_ENCODING = MidDisplayTextFormat.UCS2;

    private final MobileIDConfigurationProvider confProvider;
    private final MidClient client;
    private final ManagerService managerService;

    public MobileIDRESTAuthClient(MobileIDConfigurationProvider confProvider, MidClient client, ManagerService managerService) {
        this.confProvider = confProvider;
        this.client = client;
        this.managerService = managerService;
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
                .withDisplayTextFormat(isServiceNameUsingSpecialCharacters(managerService.getServiceShortName().orElse(confProvider.getMessageToDisplay())) ? SPECIAL_CHARACTERS_DISPLAY_ENCODING : DISPLAY_ENCODING)
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
        MidAuthenticationResponseValidator validator = new MidAuthenticationResponseValidator();
        try {
            return validator.validate(authentication);
        } catch (MidInternalErrorException e) {
            throw new ExternalServiceHasFailedException(MobileIDErrorMessage.TECHNICAL, "Authentication validation failed", e);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error occurred during authentication validation", e);
        }
    }

    private static boolean isServiceNameUsingSpecialCharacters(String serviceName) {
        Pattern p = Pattern.compile("[а-яА-ЯЁё]", Pattern.CASE_INSENSITIVE);
        String[] specialCharacters = { "Õ", "Š", "Ž", "š", "ž", "õ", "Ą", "Č", "Ę", "Ė", "Į", "Š", "Ų", "Ū", "Ž", "ą", "č", "ę", "ė", "į", "š", "ų", "ū", "ž" };
        Matcher m = p.matcher(serviceName);
        boolean isSpecialCharacterIncluded = m.find();
        return Arrays.stream(specialCharacters).anyMatch(serviceName::contains) || isSpecialCharacterIncluded;
    }

}
