package ee.ria.sso.service.idcard;

import com.google.common.base.Splitter;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationFailedException;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import ee.ria.sso.utils.EstonianIdCodeUtil;
import ee.ria.sso.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.apereo.inspektr.audit.annotation.Audit;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Map;

@ConditionalOnProperty("id-card.enabled")
@Service
@Slf4j
public class IDCardAuthenticationService extends AbstractService {

    private final StatisticsHandler statistics;
    private final IDCardConfigurationProvider configurationProvider;
    private final Map<String, X509Certificate> trustedCertificates;
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
            this.trustedCertificates = applicationContext.getBean("idCardTrustedCertificatesMap", Map.class);
        else
            this.trustedCertificates = null;
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
            this.validateUserCert(certificate);

            if (this.configurationProvider.isOcspEnabled())
                this.checkCert(certificate);

            TaraCredential credential = createUserCredential(certificate);
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

            String localizedErrorMessage = this.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR);

            if (exception instanceof AuthenticationFailedException) {
                AuthenticationFailedException authenticationFailedException = (AuthenticationFailedException) exception;
                String messageKey = authenticationFailedException.getErrorMessageKeyOrDefault(Constants.MESSAGE_KEY_GENERAL_ERROR);
                localizedErrorMessage = this.getMessage(messageKey, Constants.MESSAGE_KEY_GENERAL_ERROR);
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


    private void validateUserCert(X509Certificate x509Certificate) {
        try {
            x509Certificate.checkValidity();
        } catch (CertificateNotYetValidException e) {
            throw new AuthenticationFailedException("message.idc.certnotyetvalid",
                    "User certificate is not yet valid", e);
        } catch (CertificateExpiredException e) {
            throw new AuthenticationFailedException("message.idc.certexpired",
                    "User certificate is expired", e);
        }
    }

    private void checkCert(X509Certificate x509Certificate) {
        X509Certificate issuerCert = this.findIssuerCertificate(x509Certificate);

        if (issuerCert == null) {
            log.error("Issuer cert not found");
            throw new IllegalStateException("Issuer cert not found from setup");
        }

        try {
            x509Certificate.verify(issuerCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            throw new IllegalStateException("Failed to verify user certificate", e);
        }

        try {
            this.ocspValidator.validate(x509Certificate, issuerCert, new OCSPValidator.OCSPConfiguration(
                    configurationProvider.getOcspUrl(),
                    trustedCertificates,
                    configurationProvider.getOcspAcceptedClockSkew(),
                    configurationProvider.getOcspResponseLifetime()
            ));
        } catch (OCSPValidationException e) {
            String errorMessageKey = "message.idc.error";
            if (e.getCause() != null) errorMessageKey = String.format("message.idc.%s", e.getStatus().name().toLowerCase());
            throw new AuthenticationFailedException(errorMessageKey, "OCSP validation failed", e);
        }
    }

    private X509Certificate findIssuerCertificate(X509Certificate userCertificate) {
        String issuerCN = X509Utils.getIssuerCNFromCertificate(userCertificate);
        log.debug("IssuerCN extracted: {}", issuerCN);
        return trustedCertificates.get(issuerCN);
    }

    private TaraCredential createUserCredential(X509Certificate userCertificate) {
        Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(
                userCertificate.getSubjectDN().getName()
        );

        return new TaraCredential(
                AuthenticationType.IDCard,
                EstonianIdCodeUtil.getEEPrefixedEstonianIdCode(params.get("SERIALNUMBER")),
                params.get("GIVENNAME"),
                params.get("SURNAME")
        );
    }

}
