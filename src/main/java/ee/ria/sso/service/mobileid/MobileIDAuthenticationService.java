package ee.ria.sso.service.mobileid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.oidc.TaraScope;
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
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.List;
import java.util.Locale;

import static ee.ria.sso.statistics.StatisticsOperation.START_AUTH;
import static ee.ria.sso.statistics.StatisticsOperation.SUCCESSFUL_AUTH;
import static org.springframework.util.Assert.notNull;

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
        notNull(credential, "PreAuthenticationCredential is missing!");

        setInterfaceLanguage();

        String mobileNumber = getPhoneNumber(credential);
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
            action = "MID_AUTHENTICATION_STATUS_POLL_CANCEL",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event cancelAuthenticationSessionStatusChecking(RequestContext context) {

        notNull(context, "Request context cannot be null");

        try {
            Integer checkCount = context.getFlowScope().get(Constants.AUTH_COUNT, Integer.class);
            notNull(checkCount, "Polling count in request context is missing");

            MobileIDSession authSession = context.getFlowScope().get(Constants.MOBILE_ID_AUTHENTICATION_SESSION, MobileIDSession.class);
            notNull(authSession, "Mobile-ID session in request context is missing");

            log.info("Mobile-ID authentication session status checking canceled by the user <count:{}>, <sessionId:{}>",
                    checkCount, authSession.getSessionId());
            logEvent(context, new IllegalStateException("Canceled by the user in TARA"), AuthenticationType.MobileID);

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (Exception e) {
            logEvent(context, e, AuthenticationType.MobileID);
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
                       .put(CasWebflowConstants.VAR_ID_CREDENTIAL, constructTaraCredential(authIdentity, context));
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

    private TaraCredential constructTaraCredential(AuthenticationIdentity authIdentity, RequestContext context) {
        if (isPhoneNumberRequested(context)) {
            final PreAuthenticationCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", PreAuthenticationCredential.class);
            String mobileNumber = getPhoneNumber(credential);

            return new MobileIDCredential(
                    confProvider.getCountryCode() + authIdentity.getIdentityCode(),
                    authIdentity.getGivenName(),
                    authIdentity.getSurname(),
                    mobileNumber);
        }

        return new MobileIDCredential(
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

    private String getPhoneNumber(PreAuthenticationCredential credential) {
        return StringUtils.isBlank(credential.getMobileNumber()) ? credential.getMobileNumber() : confProvider.getAreaCode() + credential.getMobileNumber();
    }

    private boolean isPhoneNumberRequested(RequestContext context) {
        List<TaraScope> scopes = context.getExternalContext().getSessionMap().get(Constants.TARA_OIDC_SESSION_SCOPES, List.class, null);
        return scopes != null && scopes.contains(TaraScope.PHONE);
    }

    private void setInterfaceLanguage() {
        Locale locale = LocaleContextHolder.getLocale();

        if (Locale.ENGLISH.getLanguage().equalsIgnoreCase(locale.getLanguage())) {
            confProvider.setLanguage("ENG");
        } else if (Locale.forLanguageTag("ru").getLanguage().equalsIgnoreCase(locale.getLanguage())) {
            confProvider.setLanguage("RUS");
        } else {
            confProvider.setLanguage("EST");
        }
    }

    private void logEvent(RequestContext context, Exception e) {
        logEvent(context, e, AuthenticationType.MobileID);
    }
}
