package ee.ria.sso.service.mobileid;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.statistics.StatisticsHandler;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.io.IOException;
import java.util.Arrays;

import static com.codeborne.security.AuthenticationException.Code.*;
import static ee.ria.sso.statistics.StatisticsOperation.START_AUTH;
import static ee.ria.sso.statistics.StatisticsOperation.SUCCESSFUL_AUTH;

@ConditionalOnProperty("mobile-id.enabled")
@Service
@Slf4j
public class MobileIDAuthenticationService extends AbstractService {

    private final MobileIDConfigurationProvider configurationProvider;
    private final MobileIDAuthenticatorWrapper mobileIDAuthenticator;

    public MobileIDAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                         StatisticsHandler statistics,
                                         MobileIDConfigurationProvider configurationProvider,
                                         MobileIDAuthenticatorWrapper mobileIDAuthenticator) {
        super(statistics, messageSource);
        this.configurationProvider = configurationProvider;
        this.mobileIDAuthenticator = mobileIDAuthenticator;
        this.initMobileIDAuthenticator();
    }

    private void initMobileIDAuthenticator()  {
        this.mobileIDAuthenticator.setDigidocServiceURL(configurationProvider.getServiceUrl());
        this.mobileIDAuthenticator.setLanguage(configurationProvider.getLanguage());
        this.mobileIDAuthenticator.setLoginMessage(configurationProvider.getMessageToDisplay());
        this.mobileIDAuthenticator.setServiceName(configurationProvider.getServiceName());
    }

    @Audit(
            action = "MID_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event startLoginByMobileID(RequestContext context) {
        final PreAuthenticationCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", PreAuthenticationCredential.class);
        Assert.notNull(credential, "PreAuthenticationCredential is missing!");
        try {
            logEvent(context, AuthenticationType.MobileID, START_AUTH);
            if (log.isDebugEnabled()) {
                log.debug("Starting mobile ID login: <number:{}>, <ssn:{}>", credential.getMobileNumber(), credential.getPrincipalCode());
            }

            this.validateCredential(credential);
            MobileIDSession mobileIDSession = this.mobileIDAuthenticator.startLogin(credential.getPrincipalCode(),
                    this.configurationProvider.getCountryCode(), credential.getMobileNumber());
            if (log.isDebugEnabled()) {
                log.debug("Login response received ...");
            }
            context.getFlowScope().put(Constants.MOBILE_CHALLENGE, mobileIDSession.challenge);
            context.getFlowScope().put(Constants.MOBILE_SESSION, mobileIDSession);
            context.getFlowScope().put(Constants.AUTH_COUNT, 0);

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);

        } catch (AuthenticationException e) {
            logEvent(context, e, AuthenticationType.MobileID);
            if (Arrays.asList(USER_PHONE_ERROR, NO_AGREEMENT, CERTIFICATE_REVOKED, NOT_ACTIVATED, NOT_VALID).contains(e.getCode())) {
                String messageKey = String.format("message.mid.%s", e.getCode().name().toLowerCase().replace("_", ""));
                throw new UserAuthenticationFailedException(messageKey, String.format("User authentication failed! DDS MobileAuthenticate returned an error (code: %s)", e.getCode()));
            } else if (Arrays.asList(AUTHENTICATION_ERROR, USER_CERTIFICATE_MISSING, UNABLE_TO_TEST_USER_CERTIFICATE).contains(e.getCode())
                    || (e.getCode() == SERVICE_ERROR && e.getCause() instanceof IOException)) {
                throw new ExternalServiceHasFailedException("message.mid.error", String.format("Technical problems with DDS! DDS MobileAuthenticate returned an error (code: %s)", e.getCode()));
            } else {
                throw new IllegalStateException(String.format("Unexpected error returned by DDS MobileAuthenticate (code: %s)!", e.getCode()), e);
            }
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
            MobileIDSession session = context.getFlowScope().get(Constants.MOBILE_SESSION, MobileIDSession.class);
            int checkCount = context.getFlowScope().get(Constants.AUTH_COUNT, Integer.class);

            log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount, session.sessCode);

            if (this.mobileIDAuthenticator.isLoginComplete(session)) {
                TaraCredential credential = new TaraCredential(AuthenticationType.MobileID, "EE" + session.personalCode, session.firstName, session.lastName);
                context.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);
                logEvent(context, AuthenticationType.MobileID, SUCCESSFUL_AUTH);

                return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
            } else {
                context.getFlowScope().put(Constants.AUTH_COUNT, ++checkCount);
                return new Event(this, Constants.EVENT_OUTSTANDING);
            }

        } catch (AuthenticationException e) {
            logEvent(context, e, AuthenticationType.MobileID);
            if (Arrays.asList(EXPIRED_TRANSACTION, USER_CANCEL, MID_NOT_READY, PHONE_ABSENT, SENDING_ERROR, SIM_ERROR, NOT_VALID).contains(e.getCode())) {
                String messageKey = String.format("message.mid.%s", e.getCode().name().toLowerCase().replace("_", ""));
                throw new UserAuthenticationFailedException(messageKey, String.format("User authentication failed! DDS GetMobileAuthenticateStatus returned an error (code: %s)", e.getCode()));
            } else if (INTERNAL_ERROR == e.getCode() || e.getCode() == SERVICE_ERROR && e.getCause() instanceof IOException) {
                throw new ExternalServiceHasFailedException("message.mid.error", String.format("Technical problems with DDS! DDS GetMobileAuthenticateStatus returned an error (code: %s)", e.getCode()));
            } else {
                throw new IllegalStateException(String.format("Unexpected error returned by DDS GetMobileAuthenticateStatus (code: %s)", e.getCode()), e);
            }
        } catch (Exception e) {
            logEvent(context, e, AuthenticationType.MobileID);
            throw e;
        }
    }

    private void validateCredential(PreAuthenticationCredential credential) {
        if (!StringUtils.isNumeric(credential.getPrincipalCode())) {
            throw new UserAuthenticationFailedException("message.mid.invalidcode", String.format("User provided invalid idCode: <%s>", credential.getPrincipalCode()));
        }
        if (StringUtils.isBlank(credential.getMobileNumber()) || !credential.getMobileNumber().matches("^\\d+$")) {
            throw new UserAuthenticationFailedException("message.mid.invalidnumber", String.format("User provided invalid mobileNumber: <%s>", credential.getMobileNumber()));
        }
    }
}
