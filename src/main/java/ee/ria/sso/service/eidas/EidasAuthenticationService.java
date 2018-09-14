package ee.ria.sso.service.eidas;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.EidasAuthenticationFailedException;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.model.AuthenticationResult;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@ConditionalOnProperty("eidas.enabled")
@Service
@Slf4j
public class EidasAuthenticationService extends AbstractService {

    private final StatisticsHandler statistics;
    private final EidasAuthenticator eidasAuthenticator;

    public EidasAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                      StatisticsHandler statistics,
                                      EidasAuthenticator eidasAuthenticator) {
        super(messageSource);
        this.statistics = statistics;
        this.eidasAuthenticator = eidasAuthenticator;
    }

    @Audit(
            action = "EIDAS_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event startLoginByEidas(RequestContext context) {
        final TaraCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", TaraCredential.class);
        try {
            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.eIDAS, StatisticsOperation.START_AUTH
            ));
            if (log.isDebugEnabled()) {
                log.debug("Starting eIDAS login: <country:{}>", credential.getCountry());
            }

            String relayState = UUID.randomUUID().toString();
            context.getExternalContext().getSessionMap().put("service", context.getFlowScope().get("service"));
            context.getExternalContext().getSessionMap().put("relayState", relayState);
            LevelOfAssurance loa = (LevelOfAssurance) context.getExternalContext().getSessionMap().get("taraAuthorizeRequestLevelOfAssurance");
            byte[] authnRequest = this.eidasAuthenticator.authenticate(credential.getCountry(), relayState, loa);
            HttpServletResponse response = (HttpServletResponse) context.getExternalContext().getNativeResponse();
            response.setContentType("text/html; charset=UTF-8");
            try (OutputStream out = response.getOutputStream()) {
                out.write(authnRequest);
                out.flush();
            }
            context.getExternalContext().recordResponseComplete();
            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, e);
        }
    }

    @Audit(
            action = "EIDAS_AUTHENTICATION_CALLBACK",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event checkLoginForEidas(RequestContext context) {
        try {
            HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
            validateRelayState(context);

            TaraCredential credential = getCredentialFromAuthResult(
                    this.eidasAuthenticator.getAuthenticationResult(request)
            );

            context.getFlowExecutionContext().getActiveSession().getScope().put("credential", credential);
            context.getFlowScope().put("service", context.getExternalContext().getSessionMap().get("service"));

            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.eIDAS, StatisticsOperation.SUCCESSFUL_AUTH
            ));

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, e);
        }
    }

    private RuntimeException handleException(RequestContext context, Exception exception) {
        try {
            try {
                this.statistics.collect(new StatisticsRecord(
                        LocalDateTime.now(), getServiceClientId(context), AuthenticationType.eIDAS, exception.getMessage()));
            } catch (Exception e) {
                log.error("Failed to collect error statistics!", e);
            }

            String localizedErrorMessage = null;

            if (exception instanceof EidasAuthenticationFailedException) {
                localizedErrorMessage = this.getMessage("message.eidas.authfailed", "message.eidas.error");
            }

            if (StringUtils.isEmpty(localizedErrorMessage)) {
                localizedErrorMessage = this.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR);
            }

            return new TaraAuthenticationException(localizedErrorMessage, exception);
        } finally {
            clearFlowScope(context);
        }
    }

    private static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }

    private void validateRelayState(RequestContext context) {
        String relayState = ((HttpServletRequest)context.getExternalContext().getNativeRequest()).getParameter("RelayState");

        if (context.getExternalContext().getSessionMap().contains("relayState") && context.getExternalContext().getSessionMap().get("relayState").equals(relayState)) {
            context.getExternalContext().getSessionMap().remove("relayState");
        } else {
            throw new IllegalStateException("SAML response's relay state (" + relayState + ") not found among previously stored relay states!");
        }
    }

    private TaraCredential getCredentialFromAuthResult(byte[] authResultBytes) throws IOException {
        AuthenticationResult authResult = new ObjectMapper().readValue(
                new String(authResultBytes, StandardCharsets.UTF_8), AuthenticationResult.class
        );

        Map<String, String> authResultAttributes = authResult.getAttributes();
        String principalCode = getFormattedPersonIdentifier(authResultAttributes.get("PersonIdentifier"));
        String firstName = authResultAttributes.get("FirstName");
        String lastName = authResultAttributes.get("FamilyName");

        TaraCredential credential = new TaraCredential(AuthenticationType.eIDAS, principalCode, firstName, lastName);
        credential.setDateOfBirth(authResultAttributes.get("DateOfBirth"));

        String loa = authResult.getLevelOfAssurance();
        if (loa != null) credential.setLevelOfAssurance(LevelOfAssurance.findByFormalName(loa));

        return credential;
    }

    private String getFormattedPersonIdentifier(String personIdentifier) {
        String[] parts = personIdentifier.split("/");
        return parts[0] + parts[2];
    }

}
