package ee.ria.sso.service.eidas;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.EidasAuthenticationFailedException;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.common.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.model.AuthenticationResult;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
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
    private final EidasConfigurationProvider configurationProvider;
    private final EidasAuthenticator eidasAuthenticator;

    public EidasAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                      StatisticsHandler statistics,
                                      EidasConfigurationProvider configurationProvider,
                                      EidasAuthenticator eidasAuthenticator) {
        super(messageSource);
        this.statistics = statistics;
        this.configurationProvider = configurationProvider;
        this.eidasAuthenticator = eidasAuthenticator;

        this.eidasAuthenticator.setEidasClientUrl(configurationProvider.getServiceUrl());
    }

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
            context.getExternalContext().getSessionMap().put(relayState, context.getFlowScope().get("service"));
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

    public Event checkLoginForEidas(RequestContext context) {
        try {
            HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
            String relayState = request.getParameter("RelayState");
            validateRelayState(relayState, context);

            TaraCredential credential = getCredentialFromAuthResult(
                    this.eidasAuthenticator.getAuthenticationResult(request)
            );

            context.getFlowExecutionContext().getActiveSession().getScope().put("credential", credential);
            context.getFlowScope().put("service", context.getExternalContext().getSessionMap().get(relayState));

            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.eIDAS, StatisticsOperation.SUCCESSFUL_AUTH
            ));

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, e);
        }
    }

    private RuntimeException handleException(RequestContext context, Exception exception) {
        clearFlowScope(context);
        this.statistics.collect(new StatisticsRecord(
                LocalDateTime.now(), getServiceClientId(context), AuthenticationType.eIDAS, exception.getMessage()
        ));

        String localizedErrorMessage = null;

        if (exception instanceof EidasAuthenticationFailedException) {
            localizedErrorMessage = this.getMessage("message.eidas.authfailed", "message.eidas.error");
        }

        if (StringUtils.isEmpty(localizedErrorMessage)) {
            localizedErrorMessage = this.getMessage("message.general.error");
        }

        return new TaraAuthenticationException(localizedErrorMessage, exception);
    }

    private static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }

    private void validateRelayState(String relayState, RequestContext context) {
        if (StringUtils.isEmpty(relayState) || !context.getExternalContext().getSessionMap().contains(relayState)) {
            throw new RuntimeException("SAML response's relay state (" + relayState + ") not found among previously stored relay states!");
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
