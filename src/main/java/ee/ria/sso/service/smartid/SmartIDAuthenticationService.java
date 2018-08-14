package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.TaraCredentialsException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.service.smartid.SmartIDClient.AuthenticationRequest;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.exception.RequestForbiddenException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.ws.rs.ClientErrorException;
import java.time.LocalDateTime;

@ConditionalOnProperty("smart-id.enabled")
@Service
public class SmartIDAuthenticationService extends AbstractService {

    public static final CertificateLevel DEFAULT_CERTIFICATE_LEVEL = CertificateLevel.QUALIFIED;

    protected static final String EVENT_SUCCESSFUL = "success";
    protected static final String EVENT_OUTSTANDING = "outstanding";

    private static final Logger LOGGER = LoggerFactory.getLogger(SmartIDAuthenticationService.class);
    private static final AuthenticationType AUTHENTICATION_TYPE = AuthenticationType.SmartID;

    private final StatisticsHandler statisticsHandler;
    private final SmartIDClient smartIdClient;
    private final SmartIDConfigurationProvider confProvider;
    private final SmartIDAuthenticationValidatorWrapper authResponseValidator;

    @Autowired
    public SmartIDAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                        StatisticsHandler statisticsHandler,
                                        SmartIDClient smartIdClient,
                                        SmartIDConfigurationProvider confProvider,
                                        SmartIDAuthenticationValidatorWrapper authResponseValidator) {
        super(messageSource);
        this.statisticsHandler = statisticsHandler;
        this.smartIdClient = smartIdClient;
        this.confProvider = confProvider;
        this.authResponseValidator = authResponseValidator;
    }

    public Event initSmartIdAuthenticationSession(RequestContext context) {
        final TaraCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get(Constants.CREDENTIAL, TaraCredential.class);
        final String personIdentifier = credential.getPrincipalCode();

        /* Currently only EE supported */
        final String personCountry = "EE";

        LOGGER.info("Starting Smart-ID authentication: <country:{}>, <ssn:{}>", personCountry, personIdentifier);
        try {
            collectStatistics(context, StatisticsOperation.START_AUTH);
            validateLoginFields(personIdentifier);

            AuthenticationRequest authRequest = formSubjectAuthenticationRequest(personIdentifier, personCountry);
            AuthenticationSessionResponse authResponse = smartIdClient.authenticateSubject(authRequest);

            LOGGER.info("Authentication response received");
            writeAuthSessionToFlowContext(context, authRequest, authResponse.getSessionId());
            return new Event(this, EVENT_SUCCESSFUL);
        } catch (TaraCredentialsException e) {
            throw handleException(context, e, e.getKey());
        } catch (UserAccountNotFoundException e) {
            throw handleException(context, e, SmartIDErrorMessage.USER_ACCOUNT_NOT_FOUND);
        } catch (RequestForbiddenException e) {
            throw handleException(context, e, SmartIDErrorMessage.REQUEST_FORBIDDEN);
        } catch (ClientErrorException e) {
            throw handleSmartIDClientException(context, e);
        } catch (Exception e) {
            throw handleException(context, e, SmartIDErrorMessage.GENERAL);
        }
    }

    public Event checkSmartIdAuthenticationSessionStatus(RequestContext context) {
        AuthenticationSession authSession =
                context.getFlowScope().get(Constants.SMART_ID_AUTHENTICATION_SESSION, AuthenticationSession.class);

        LOGGER.info("Authentication session status checking attempt <count:{}>, <sessionId:{}>",
                authSession.getStatusCheckCount(), authSession.getSessionId());
        try {
            SessionStatus sessionStatus = smartIdClient.getSessionStatus(authSession.getSessionId());
            if (StringUtils.equals(sessionStatus.getState(), SessionState.COMPLETE.name())) {
                LOGGER.info("Authentication session complete");
                SmartIdAuthenticationResult validationResult = authResponseValidator
                        .validateAuthenticationResponse(sessionStatus, authSession.getAuthenticationHash(), authSession.getCertificateLevel());

                collectStatistics(context, StatisticsOperation.SUCCESSFUL_AUTH);
                writePersonDetailsToFlowContext(context, validationResult.getAuthenticationIdentity());
                return new Event(this, EVENT_SUCCESSFUL);
            } else {
                LOGGER.info("Authentication session not complete yet");
                authSession.increaseStatusCheckCount();
                return new Event(this, EVENT_OUTSTANDING);
            }
        } catch (SessionNotFoundException e) {
            throw handleException(context, e, SmartIDErrorMessage.SESSION_NOT_FOUND);
        } catch (SessionValidationException e) {
            throw handleException(context, e, e.getErrorMessageKey());
        } catch (ClientErrorException e) {
            throw handleSmartIDClientException(context, e);
        } catch (Exception e) {
            throw handleException(context, e, SmartIDErrorMessage.GENERAL);
        }
    }

    private void validateLoginFields(String personIdentifier) {
        if (StringUtils.isBlank(personIdentifier)) {
            throw new TaraCredentialsException(SmartIDErrorMessage.PERSON_IDENTIFIER_MISSING, personIdentifier);
        }

        if (!StringUtils.isNumeric(personIdentifier) || personIdentifier.length() != 11) {
            throw new TaraCredentialsException(SmartIDErrorMessage.INVALID_PERSON_IDENTIFIER, personIdentifier);
        }
    }

    private AuthenticationRequest formSubjectAuthenticationRequest(String personIdentifier, String personCountry) {
        return AuthenticationRequest.builder()
                .personIdentifier(personIdentifier)
                .personCountry(personCountry)
                .certificateLevel(DEFAULT_CERTIFICATE_LEVEL)
                .authenticationHash(AuthenticationHash.generateRandomHash(confProvider.getAuthenticationHashType()))
                .build();
    }

    private void writeAuthSessionToFlowContext(RequestContext context, AuthenticationRequest authRequest, String sessionId) {
        AuthenticationSession authSession = AuthenticationSession.builder()
                .sessionId(sessionId)
                .authenticationHash(authRequest.getAuthenticationHash())
                .certificateLevel(authRequest.getCertificateLevel())
                .build();

        MutableAttributeMap<Object> flowScope = context.getFlowScope();
        flowScope.put(Constants.SMART_ID_VERIFICATION_CODE, authRequest.getAuthenticationHash().calculateVerificationCode());
        flowScope.put(Constants.SMART_ID_AUTHENTICATION_SESSION, authSession);
    }

    private void writePersonDetailsToFlowContext(RequestContext context, AuthenticationIdentity authIdentity) {
        TaraCredential credential = formTaraCredentials(authIdentity);
        context.getFlowExecutionContext().getActiveSession().getScope().put(Constants.CREDENTIAL, credential);
    }

    private TaraCredential formTaraCredentials(AuthenticationIdentity authIdentity) {
        return new TaraCredential(
                AUTHENTICATION_TYPE,
                authIdentity.getCountry() + authIdentity.getIdentityCode(),
                authIdentity.getGivenName(),
                authIdentity.getSurName()
        );
    }

    private void collectStatistics(RequestContext context, StatisticsOperation statisticsOperation) {
        StatisticsRecord statisticsRecord = new StatisticsRecord(
                LocalDateTime.now(), getServiceClientId(context), AUTHENTICATION_TYPE, statisticsOperation
        );
        System.out.println(statisticsRecord);
        statisticsHandler.collect(statisticsRecord);
    }

    private void collectErrorStatistics(RequestContext context, String exceptionMessage) {
        StatisticsRecord statisticsRecord = new StatisticsRecord(
                LocalDateTime.now(), getServiceClientId(context), AUTHENTICATION_TYPE, exceptionMessage
        );
        System.out.println(statisticsRecord);
        statisticsHandler.collect(statisticsRecord);
    }

    private RuntimeException handleSmartIDClientException(RequestContext context, ClientErrorException e) {
        switch (e.getMessage()) {
            case "HTTP 471" : /* No suitable account of requested type found, but user has some other accounts. */
                throw handleException(context, e, SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT);
            case "HTTP 472" : /* Person should view app or self-service portal now. */
                throw handleException(context, e, SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE);
            case "HTTP 480" : /* The client (i.e. client-side implementation of this API) is old and not supported any more. Relying Party must contact customer support. */
                throw handleException(context, e, SmartIDErrorMessage.GENERAL);
            case "HTTP 580" : /* System is under maintenance, retry later. */
                throw handleException(context, e, SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE);
            default :
                throw handleException(context, e, SmartIDErrorMessage.GENERAL);
        }
    }

    private RuntimeException handleException(RequestContext context, Exception exception, String errorMessageKey) {
        clearFlowScope(context);
        LOGGER.info("Process failed due to exception of type <{}> with message <{}> and errorMessageKey <{}>",
                exception.getClass(),
                exception.getMessage(),
                errorMessageKey);
//        TODO: Speki järgi peaks olema lokaliseeritud veasõnum, äkki peaks olema hoopis veakood?
        collectErrorStatistics(context, exception.getMessage());
        String localizedErrorMessage = getMessage(errorMessageKey);
        return new TaraAuthenticationException(localizedErrorMessage, exception);
    }

    private static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }
}
