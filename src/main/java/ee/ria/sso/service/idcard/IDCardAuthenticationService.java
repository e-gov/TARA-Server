package ee.ria.sso.service.idcard;

import com.google.common.base.Splitter;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationFailedException;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import ee.ria.sso.utils.X509Utils;
import ee.ria.sso.validators.OCSPValidationException;
import ee.ria.sso.validators.OCSPValidator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Map;

@ConditionalOnProperty("id-card.enabled")
@Service
@Slf4j
public class IDCardAuthenticationService extends AbstractService {

    private final StatisticsHandler statistics;
    private final IDCardConfigurationProvider configurationProvider;
    private final Map<String, X509Certificate> issuerCertificates;
    private final OCSPValidator ocspValidator;

    public IDCardAuthenticationService(TaraResourceBundleMessageSource messageSource,
                                       StatisticsHandler statistics,
                                       IDCardConfigurationProvider configurationProvider,
                                       ApplicationContext applicationContext,
                                       OCSPValidator ocspValidator) {
        super(messageSource);
        this.statistics = statistics;
        this.configurationProvider = configurationProvider;
        this.ocspValidator = ocspValidator;

        if (configurationProvider.isOcspEnabled())
            this.issuerCertificates = applicationContext.getBean("idIssuerCertificatesMap", Map.class);
        else
            this.issuerCertificates = null;
    }

    @Audit(
            action = "ESTEID_AUTHENTICATION",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event loginByIDCard(RequestContext context) {
        SharedAttributeMap<Object> sessionMap = this.getSessionMap(context);
        try {
            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.IDCard, StatisticsOperation.START_AUTH
            ));

            X509Certificate certificate = sessionMap.get(Constants.CERTIFICATE_SESSION_ATTRIBUTE, X509Certificate.class);
            if (certificate == null)
                throw new AuthenticationFailedException("message.idc.nocertificate", "Unable to find certificate from session");
            if (this.configurationProvider.isOcspEnabled())
                this.checkCert(certificate);

            Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(certificate.getSubjectDN().getName());
            String principalCode = "EE" + params.get("SERIALNUMBER");
            String firstName = params.get("GIVENNAME");
            String lastName = params.get("SURNAME");

            TaraCredential credential = new TaraCredential(AuthenticationType.IDCard, principalCode, firstName, lastName);
            context.getFlowExecutionContext().getActiveSession().getScope().put("credential", credential);

            this.statistics.collect(new StatisticsRecord(
                    LocalDateTime.now(), getServiceClientId(context), AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH
            ));

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, e);
        } finally {
            sessionMap.remove(Constants.CERTIFICATE_SESSION_ATTRIBUTE);
        }
    }

    private RuntimeException handleException(RequestContext context, Exception exception) {
        try {
            try {
                this.statistics.collect(new StatisticsRecord(
                        LocalDateTime.now(), getServiceClientId(context), AuthenticationType.IDCard, exception.getMessage()));
            } catch (Exception e) {
                log.error("Failed to collect error statistics!", e);
            }

            String localizedErrorMessage = null;

            if (exception instanceof OCSPValidationException) {
                String messageKey = String.format("message.idc.%s", ((OCSPValidationException) exception).getStatus().name().toLowerCase());
                localizedErrorMessage = this.getMessage(messageKey, "message.idc.error");
            } else if (exception instanceof AuthenticationFailedException) {
                AuthenticationFailedException authenticationFailedException = (AuthenticationFailedException) exception;
                String messageKey = authenticationFailedException.getErrorMessageKeyOrDefault(Constants.MESSAGE_KEY_GENERAL_ERROR);
                localizedErrorMessage = this.getMessage(messageKey, Constants.MESSAGE_KEY_GENERAL_ERROR);
            }

            if (StringUtils.isBlank(localizedErrorMessage)) {
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


    private void checkCert(X509Certificate x509Certificate) {
        X509Certificate issuerCert = this.findIssuerCertificate(x509Certificate);
        if (issuerCert != null) {
            this.ocspValidator.validate(x509Certificate, issuerCert, configurationProvider.getOcspUrl(), issuerCertificates);
        } else {
            log.error("Issuer cert not found");
            throw new IllegalStateException("Issuer cert not found from setup");
        }
    }

    private X509Certificate findIssuerCertificate(X509Certificate userCertificate) {
        String issuerCN = X509Utils.getSubjectCNFromCertificate(userCertificate);
        log.debug("IssuerCN extracted: {}", issuerCN);
        return issuerCertificates.get(issuerCN);
    }

}
