package ee.ria.sso.service.mobileid;

import com.codeborne.security.AuthenticationException;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.service.mobileid.rest.MobileIDErrorMessage;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.sk.mid.MidInputUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import static ee.ria.sso.statistics.StatisticsOperation.START_AUTH;
import static ee.ria.sso.statistics.StatisticsOperation.SUCCESSFUL_AUTH;

@ConditionalOnProperty("mobile-id.enabled")
@Service
@Slf4j
public class MobileIDAuthenticationService extends AbstractService {

    private final MobileIDConfigurationProvider confProvider;
    private final MobileIDAuthenticationClient authenticationClient;

    public MobileIDAuthenticationService(StatisticsHandler statistics,
                                         MobileIDConfigurationProvider confProvider,
                                         MobileIDAuthenticationClient authenticationClient) {
        super(statistics);
        this.confProvider = confProvider;
        this.authenticationClient = authenticationClient;
    }

    @Audit(
            action = "MID_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event startLoginByMobileID(RequestContext context) {
        final PreAuthenticationCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", PreAuthenticationCredential.class);
        Assert.notNull(credential, "PreAuthenticationCredential is missing!");


        String mobileNumber = StringUtils.isBlank(credential.getMobileNumber()) ? credential.getMobileNumber() : confProvider.getAreaCode() + credential.getMobileNumber();
        log.info("Starting Mobile-ID authentication: <mobileNumber:{}>, <identityCode:{}>", mobileNumber, credential.getPrincipalCode());
        try {
            logEvent(context, AuthenticationType.MobileID, START_AUTH);

            this.validateCredential(credential.getPrincipalCode(), mobileNumber);

            MobileIDSession session = authenticationClient.initAuthentication(credential.getPrincipalCode(), confProvider.getCountryCode(), mobileNumber);
            log.info("Successful authentication initiation response received <sessionId:{}>", session.getSessionId());
            context.getFlowScope().put(Constants.MOBILE_ID_VERIFICATION_CODE, session.getVerificationCode());
            context.getFlowScope().put(Constants.MOBILE_ID_AUTHENTICATION_SESSION, session);
            context.getFlowScope().put(Constants.AUTH_COUNT, 0);

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (Exception e) {
            logEvent(context, e);
            throw e;
        }
    }

    @Audit(
            action = "MID_AUTHENTICATION_STATUS_POLL",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event checkLoginForMobileID(RequestContext context) {
        try {
            MobileIDSession session = context.getFlowScope().get(Constants.MOBILE_ID_AUTHENTICATION_SESSION, MobileIDSession.class);
            int checkCount = context.getFlowScope().get(Constants.AUTH_COUNT, Integer.class);

            log.info("Mobile-ID authentication session status checking attempt <count:{}>, <sessionId:{}>", checkCount, session.getSessionId());

            MobileIDSessionStatus sessionStatus = authenticationClient.pollAuthenticationSessionStatus(session);
            if (sessionStatus.isAuthenticationComplete()) {
                log.info("Mobile-ID authentication complete <sessionId:{}>", session.getSessionId());
                AuthenticationIdentity authIdentity = authenticationClient.getAuthenticationIdentity(session, sessionStatus);
                context.getFlowExecutionContext().getActiveSession().getScope()
                       .put(CasWebflowConstants.VAR_ID_CREDENTIAL, constructTaraCredential(authIdentity));
                logEvent(context, AuthenticationType.MobileID, SUCCESSFUL_AUTH);
                return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
            } else {
                log.info("Mobile-ID authentication not complete yet <sessionId:{}>", session.getSessionId());
                context.getFlowScope().put(Constants.AUTH_COUNT, ++checkCount);
                return new Event(this, Constants.EVENT_OUTSTANDING);
            }
        } catch (Exception e) {
            logEvent(context, e);
            throw e;
        }
    }

    private TaraCredential constructTaraCredential(AuthenticationIdentity authIdentity) {
        return new TaraCredential(AuthenticationType.MobileID,
                confProvider.getCountryCode() + authIdentity.getIdentityCode(),
                authIdentity.getGivenName(),
                authIdentity.getSurname());
    }

    private void validateCredential(String principalCode, String mobileNumber) {
        if (!MidInputUtil.isNationalIdentityNumberValid(principalCode)) {
            throw new UserAuthenticationFailedException(MobileIDErrorMessage.INVALID_IDENTITY_CODE, String.format("User provided invalid identityCode: <%s>", principalCode));
        }
        if (!MidInputUtil.isPhoneNumberValid(mobileNumber)) {
            throw new UserAuthenticationFailedException(MobileIDErrorMessage.INVALID_MOBILE_NUMBER, String.format("User provided invalid mobileNumber: <%s>", mobileNumber));
        }
    }

    private void logEvent(RequestContext context, Exception e) {
        Throwable cause = e.getCause();
        if (cause instanceof AuthenticationException) {
            logEvent(context, cause, AuthenticationType.MobileID);
        } else {
            logEvent(context, e, AuthenticationType.MobileID);
        }
    }
}