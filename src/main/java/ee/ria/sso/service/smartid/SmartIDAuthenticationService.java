package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.smartid.SmartIDConfigurationProvider;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.smartid.SmartIDClient.AuthenticationRequest;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.exception.RequestForbiddenException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.ws.rs.ClientErrorException;

import static ee.ria.sso.statistics.StatisticsOperation.START_AUTH;
import static ee.ria.sso.statistics.StatisticsOperation.SUCCESSFUL_AUTH;

@ConditionalOnProperty("smart-id.enabled")
@Service
public class SmartIDAuthenticationService extends AbstractService {

    public static final CertificateLevel DEFAULT_CERTIFICATE_LEVEL = CertificateLevel.QUALIFIED;

    private static final Logger LOGGER = LoggerFactory.getLogger(SmartIDAuthenticationService.class);
    private static final AuthenticationType AUTHENTICATION_TYPE = AuthenticationType.SmartID;

    private final SmartIDClient smartIdClient;
    private final SmartIDConfigurationProvider confProvider;
    private final SmartIDAuthenticationValidatorWrapper authResponseValidator;

    @Autowired
    public SmartIDAuthenticationService(StatisticsHandler statisticsHandler,
                                        SmartIDClient smartIdClient,
                                        SmartIDConfigurationProvider confProvider,
                                        SmartIDAuthenticationValidatorWrapper authResponseValidator) {
        super(statisticsHandler);
        this.smartIdClient = smartIdClient;
        this.confProvider = confProvider;
        this.authResponseValidator = authResponseValidator;
    }

    @Audit(
            action = "SMARTID_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event initSmartIdAuthenticationSession(RequestContext context) {
        final PreAuthenticationCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get(CasWebflowConstants.VAR_ID_CREDENTIAL, PreAuthenticationCredential.class);
        final String personIdentifier = credential.getPrincipalCode();

        /* Currently only EE supported */
        final String personCountry = "EE";

        LOGGER.info("Starting Smart-ID authentication: <country:{}>, <ssn:{}>", personCountry, personIdentifier);
        try {
            logEvent(context, AuthenticationType.SmartID, START_AUTH);
            validateLoginFields(personIdentifier);

            AuthenticationRequest authRequest = formSubjectAuthenticationRequest(personIdentifier, personCountry);
            AuthenticationSessionResponse authResponse = smartIdClient.authenticateSubject(authRequest);

            LOGGER.info("Authentication response received <sessionId:{}>", authResponse.getSessionID());
            writeAuthSessionToFlowContext(context, authRequest, authResponse.getSessionID());
            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (UserAuthenticationFailedException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw e;
        } catch (UserAccountNotFoundException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw new UserAuthenticationFailedException(SmartIDErrorMessage.USER_ACCOUNT_NOT_FOUND, e.getMessage(), e);
        } catch (RequestForbiddenException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw new UserAuthenticationFailedException(SmartIDErrorMessage.REQUEST_FORBIDDEN, e.getMessage(), e);
        } catch (ClientErrorException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw handleSmartIDClientException(e);
        } catch (Exception e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw e;
        }
    }

    @Audit(
            action = "SMARTID_AUTHENTICATION_STATUS_POLL_CANCEL",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event cancelCheckSmartIdAuthenticationSessionStatus(RequestContext context) {

        try {
            AuthenticationSession authSession =
                    context.getFlowScope().get(Constants.SMART_ID_AUTHENTICATION_SESSION, AuthenticationSession.class);
            LOGGER.info("Smart-ID authentication session status checking canceled by the user <count:{}>, <sessionId:{}>",
                    authSession.getStatusCheckCount(), authSession.getSessionId());
            logEvent(context, new IllegalStateException("Canceled by the user in TARA"), AuthenticationType.SmartID);
            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (Exception e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw e;
        }
    }

    @Audit(
            action = "SMARTID_AUTHENTICATION_STATUS_POLL",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event checkSmartIdAuthenticationSessionStatus(RequestContext context) {
        AuthenticationSession authSession =
                context.getFlowScope().get(Constants.SMART_ID_AUTHENTICATION_SESSION, AuthenticationSession.class);

        LOGGER.info("Smart-ID authentication session status checking attempt <count:{}>, <sessionId:{}>",
                authSession.getStatusCheckCount(), authSession.getSessionId());
        try {
            SessionStatus sessionStatus = smartIdClient.getSessionStatus(authSession.getSessionId());
            if (StringUtils.equals(sessionStatus.getState(), SessionState.COMPLETE.name())) {
                LOGGER.info("Smart-ID authentication session complete <sessionId:{}>", authSession.getSessionId());
                SmartIdAuthenticationResult validationResult = authResponseValidator
                        .validateAuthenticationResponse(sessionStatus, authSession.getAuthenticationHash(), authSession.getCertificateLevel());

                logEvent(context, AuthenticationType.SmartID, SUCCESSFUL_AUTH);
                writePersonDetailsToFlowContext(context, validationResult.getAuthenticationIdentity());
                return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
            } else {
                LOGGER.info("Smart-ID authentication session not complete yet <sessionId:{}>", authSession.getSessionId());
                authSession.increaseStatusCheckCount();
                return new Event(this, Constants.EVENT_OUTSTANDING);
            }
        } catch (SessionNotFoundException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw new UserAuthenticationFailedException(SmartIDErrorMessage.SESSION_NOT_FOUND, e.getMessage(), e);
        } catch (SessionValidationException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw new UserAuthenticationFailedException(e.getErrorMessageKey(), e.getMessage(), e);
        } catch (ClientErrorException e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw handleSmartIDClientException(e);
        } catch (Exception e) {
            logEvent(context, e, AuthenticationType.SmartID);
            throw e;
        }
    }

    private void validateLoginFields(String personIdentifier) {
        if (StringUtils.isBlank(personIdentifier)) {
            throw new UserAuthenticationFailedException(SmartIDErrorMessage.PERSON_IDENTIFIER_MISSING, personIdentifier);
        }

        if (!StringUtils.isNumeric(personIdentifier) || personIdentifier.length() != 11) {
            throw new UserAuthenticationFailedException(SmartIDErrorMessage.INVALID_PERSON_IDENTIFIER, personIdentifier);
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
        context.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);
    }

    private TaraCredential formTaraCredentials(AuthenticationIdentity authIdentity) {
        return new TaraCredential(
                AUTHENTICATION_TYPE,
                authIdentity.getCountry() + authIdentity.getIdentityCode(),
                authIdentity.getGivenName(),
                authIdentity.getSurName()
        );
    }

    private RuntimeException handleSmartIDClientException(ClientErrorException e) {
        switch (e.getMessage()) {
            case "HTTP 471" : /* No suitable account of requested type found, but user has some other accounts. */
                throw new UserAuthenticationFailedException(SmartIDErrorMessage.USER_DOES_NOT_HAVE_QUERY_MATCHING_ACCOUNT, e.getMessage(), e);
            case "HTTP 472" : /* Person should view app or self-service portal now. */
                throw new UserAuthenticationFailedException(SmartIDErrorMessage.UNKNOWN_REASON_INSTRUCTIONS_IN_USER_DEVICE, e.getMessage(), e);
            case "HTTP 480" : /* The client (i.e. client-side implementation of this API) is old and not supported any more. Relying Party must contact customer support. */
                throw new UserAuthenticationFailedException(SmartIDErrorMessage.GENERAL, e.getMessage(), e);
            case "HTTP 580" : /* System is under maintenance, retry later. */
                throw new ExternalServiceHasFailedException(SmartIDErrorMessage.SMART_ID_SYSTEM_UNDER_MAINTENANCE, e.getMessage(), e);
            default :
                throw new ExternalServiceHasFailedException(SmartIDErrorMessage.GENERAL, e.getMessage(), e);
        }
    }
}
