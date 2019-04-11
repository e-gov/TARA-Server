package ee.ria.sso.service.eidas;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.security.CspDirective;
import ee.ria.sso.security.CspHeaderUtil;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ee.ria.sso.Constants.TARA_OIDC_SESSION_LOA;

@ConditionalOnProperty("eidas.enabled")
@Service
@Slf4j
public class EidasAuthenticationService extends AbstractService {

    public static final Pattern VALID_PERSON_IDENTIFIER_PATTERN = Pattern.compile("^([A-Z]{2,2})\\/([A-Z]{2,2})\\/(.*)$");
    public static final Pattern VALID_COUNTRY_PATTERN = Pattern.compile("^[A-Z]{2,2}$");
    public static final String SESSION_ATTRIBUTE_COUNTRY = "country";
    public static final String SESSION_ATTRIBUTE_RELAY_STATE = "relayState";

    private final EidasAuthenticator eidasAuthenticator;

    public EidasAuthenticationService(StatisticsHandler statistics,
                                      EidasAuthenticator eidasAuthenticator) {
        super(statistics);
        this.eidasAuthenticator = eidasAuthenticator;
    }

    @Audit(
            action = "EIDAS_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event startLoginByEidas(RequestContext context) {
        final PreAuthenticationCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", PreAuthenticationCredential.class);
        log.debug("Starting eIDAS login: <country:{}>", credential.getCountry());

        try {
            validateAndStoreCountry(credential, context);
            logEvent(context, StatisticsOperation.START_AUTH);
            String relayState = generateAndStoreRelayState(context);
            LevelOfAssurance loa = context.getExternalContext().getSessionMap().get(TARA_OIDC_SESSION_LOA, LevelOfAssurance.class);
            byte[] authnRequest = eidasAuthenticator.authenticate(credential.getCountry(), relayState, loa);
            writeServletResponse(context, authnRequest);
            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (IOException e) {
            logFailureEvent(context, e);
            throw new ExternalServiceHasFailedException("message.eidas.error", "eidas-client connection has failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logFailureEvent(context, e);
            throw e;
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

            EidasCredential credential = getCredentialFromAuthResult(
                    this.eidasAuthenticator.getAuthenticationResult(request)
            );

            context.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);
            context.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, context.getExternalContext().getSessionMap().get(Constants.CAS_SERVICE_ATTRIBUTE_NAME));

            logEvent(context, StatisticsOperation.SUCCESSFUL_AUTH);
            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (EidasAuthenticationFailedException e) {
            logFailureEvent(context, e);
            throw new UserAuthenticationFailedException("message.eidas.authfailed", e.getMessage(), e);
        } catch (IOException e) {
            logFailureEvent(context, e);
            throw new ExternalServiceHasFailedException("message.eidas.error", "eidas-client connection has failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logFailureEvent(context, e);
            throw e;
        }
    }

    private void writeServletResponse(RequestContext context, byte[] authnRequest) throws IOException {
        HttpServletResponse response = (HttpServletResponse) context.getExternalContext().getNativeResponse();
        configureResponseForWriting(response, authnRequest);

        try (OutputStream out = response.getOutputStream()) {
            out.write(authnRequest);
            out.flush();
        }
        context.getExternalContext().getSessionMap().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, context.getFlowScope().get(Constants.CAS_SERVICE_ATTRIBUTE_NAME));
        context.getExternalContext().recordResponseComplete();
    }

    private static void configureResponseForWriting(HttpServletResponse response, byte[] html) {
        response.setContentType("text/html; charset=UTF-8");

        final String scriptHashes = CspHeaderUtil.generateSerializedHashListOfAllTags(html, "script");
        if (StringUtils.isNotBlank(scriptHashes)) {
            CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.SCRIPT_SRC, scriptHashes);
        }

        final String formActions = CspHeaderUtil.generateSerializedFormActionsList(html);
        if (StringUtils.isNotBlank(formActions)) {
            CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.FORM_ACTION, formActions);
        }
    }

    private void validateRelayState(RequestContext context) {
        String relayState = ((HttpServletRequest)context.getExternalContext().getNativeRequest()).getParameter("RelayState");

        if (context.getExternalContext().getSessionMap().contains(SESSION_ATTRIBUTE_RELAY_STATE) && context.getExternalContext().getSessionMap().get(SESSION_ATTRIBUTE_RELAY_STATE).equals(relayState)) {
            context.getExternalContext().getSessionMap().remove(SESSION_ATTRIBUTE_RELAY_STATE);
        } else {
            throw new IllegalStateException("SAML response's relay state (" + relayState + ") not found among previously stored relay states!");
        }
    }

    private EidasCredential getCredentialFromAuthResult(byte[] authResultBytes) throws IOException {
        EidasAuthenticationResult authResult = new ObjectMapper().readValue(
                new String(authResultBytes, StandardCharsets.UTF_8), EidasAuthenticationResult.class
        );

        Map<String, String> authResultAttributes = authResult.getAttributes();
        String principalCode = getFormattedPersonIdentifier(authResultAttributes.get("PersonIdentifier"));
        String firstName = authResultAttributes.get("FirstName");
        String lastName = authResultAttributes.get("FamilyName");
        String dateOfBirth = authResultAttributes.get("DateOfBirth");
        LevelOfAssurance loa = LevelOfAssurance.findByFormalName(authResult.getLevelOfAssurance());
        return new EidasCredential(principalCode, firstName, lastName, dateOfBirth, loa);
    }

    private String getFormattedPersonIdentifier(String personIdentifier) {
        Matcher matcher = VALID_PERSON_IDENTIFIER_PATTERN.matcher(personIdentifier);
        if (matcher.matches()) {
            return matcher.group(1) + matcher.group(3);
        } else {
            throw new ExternalServiceHasFailedException("message.eidas.error", "The person identifier has invalid format! <" + personIdentifier + ">");
        }
    }

    private String generateAndStoreRelayState(RequestContext context) {
        String relayState = UUID.randomUUID().toString();
        context.getExternalContext().getSessionMap().put(SESSION_ATTRIBUTE_RELAY_STATE, relayState);
        return relayState;
    }

    private String getCountry(RequestContext context) {
        return context.getExternalContext().getSessionMap().getString(SESSION_ATTRIBUTE_COUNTRY);
    }

    private void validateAndStoreCountry(PreAuthenticationCredential credential, RequestContext context) {
        if (StringUtils.isBlank(credential.getCountry()) || !VALID_COUNTRY_PATTERN.matcher(credential.getCountry()).matches()) {
            throw new UserAuthenticationFailedException("message.eidas.invalidcountry", String.format("User provided invalid country code: <%s>", credential.getCountry()));
        }
        context.getExternalContext().getSessionMap().put(SESSION_ATTRIBUTE_COUNTRY, credential.getCountry().toUpperCase());
    }

    private void logEvent(RequestContext context, StatisticsOperation operation) {
        String country = getCountry(context);
        if (country != null) {
            logEvent(StatisticsRecord.builder()
                    .time(LocalDateTime.now())
                    .clientId(getServiceClientId(context))
                    .method(AuthenticationType.eIDAS)
                    .operation(operation)
                    .country(country)
                    .build()
            );
        }
    }

    private void logFailureEvent(RequestContext context, Exception e) {
        String country = getCountry(context);
        if (country != null)
            logEvent(StatisticsRecord.builder()
                    .time(LocalDateTime.now())
                    .clientId(getServiceClientId(context))
                    .method(AuthenticationType.eIDAS)
                    .operation(StatisticsOperation.ERROR)
                    .country(country.toUpperCase())
                    .error(e.getMessage())
                    .build()
            );
    }
}
