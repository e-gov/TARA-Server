package ee.ria.sso.service.mobileid;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.TaraCredentialsException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.mobileid.MobileIDConfigurationProvider;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.time.LocalDateTime;

@ConditionalOnProperty("mobile-id.enabled")
@Service
@Slf4j
public class MobileIDAuthenticationService extends AbstractService {

    private final StatisticsHandler statistics;
    private final MobileIDConfigurationProvider configurationProvider;
    private final MobileIDAuthenticatorWrapper mobileIDAuthenticator;

    public MobileIDAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                         StatisticsHandler statistics,
                                         MobileIDConfigurationProvider configurationProvider,
                                         MobileIDAuthenticatorWrapper mobileIDAuthenticator) {
        super(messageSource);
        this.statistics = statistics;
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

    public Event startLoginByMobileID(RequestContext context) {
        final TaraCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", TaraCredential.class);
        try {
            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.MobileID, StatisticsOperation.START_AUTH
            ));
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
            context.getFlowScope().put(Constants.MOBILE_NUMBER, credential.getMobileNumber());
            context.getFlowScope().put(Constants.MOBILE_SESSION, mobileIDSession);
            context.getFlowScope().put(Constants.AUTH_COUNT, 0);

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, e);
        }
    }

    public Event checkLoginForMobileID(RequestContext context) {
        try {
            MobileIDSession session = context.getFlowScope().get(Constants.MOBILE_SESSION, MobileIDSession.class);
            int checkCount = context.getFlowScope().get(Constants.AUTH_COUNT, Integer.class);
            String mobileNumber = context.getFlowScope().get(Constants.MOBILE_NUMBER, String.class);
            log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount, session.sessCode);

            if (this.mobileIDAuthenticator.isLoginComplete(session)) {
                TaraCredential credential = new TaraCredential(AuthenticationType.MobileID, "EE" + session.personalCode, session.firstName, session.lastName);
                credential.setMobileNumber(getFormattedPhoneNumber(mobileNumber));

                context.getFlowExecutionContext().getActiveSession().getScope().put("credential", credential);
                this.statistics.collect(new StatisticsRecord(
                        LocalDateTime.now(), getServiceClientId(context), AuthenticationType.MobileID, StatisticsOperation.SUCCESSFUL_AUTH
                ));

                return new Event(this, "success");
            } else {
                context.getFlowScope().put(Constants.AUTH_COUNT, ++checkCount);
                return new Event(this, "outstanding");
            }
        } catch (Exception e) {
            throw this.handleException(context, e);
        }
    }

    private RuntimeException handleException(RequestContext context, Exception exception) {
        clearFlowScope(context);
        this.statistics.collect(new StatisticsRecord(
                LocalDateTime.now(), getServiceClientId(context), AuthenticationType.MobileID, exception.getMessage()
        ));

        String localizedErrorMessage = null;

        if (exception instanceof TaraCredentialsException) {
            localizedErrorMessage = this.getMessage(((TaraCredentialsException) exception).getKey(), "message.mid.error");
        } else if (exception instanceof AuthenticationException) {
            String messageKey = String.format("message.mid.%s", ((AuthenticationException) exception).getCode().name()
                    .toLowerCase().replace("_", ""));
            localizedErrorMessage = this.getMessage(messageKey, "message.mid.error");
        }

        if (StringUtils.isEmpty(localizedErrorMessage)) {
            localizedErrorMessage = this.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR);
        }

        return new TaraAuthenticationException(localizedErrorMessage, exception);
    }

    private static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }

    private void validateCredential(TaraCredential credential) {
        if (!StringUtils.isNumeric(credential.getPrincipalCode())) {
            throw new TaraCredentialsException("message.mid.invalidcode", credential.getPrincipalCode());
        }
        if (StringUtils.isBlank(credential.getMobileNumber()) || !credential.getMobileNumber().matches("^\\d+$")) {
            throw new TaraCredentialsException("message.mid.invalidnumber", credential.getMobileNumber());
        }
    }

    private String getFormattedPhoneNumber(String mobileNumber) {
        if (mobileNumber.startsWith("372")) {
            return "+" + mobileNumber;
        }
        return "+372" + mobileNumber;
    }

}
