package ee.ria.sso.service.idcard;

import com.google.common.base.Splitter;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import ee.ria.sso.utils.EstonianIdCodeUtil;
import ee.ria.sso.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.MDC;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static ee.ria.sso.Constants.MDC_ATTRIBUTE_OCSP_ID;
import static ee.ria.sso.statistics.StatisticsOperation.SUCCESSFUL_AUTH;

@Slf4j
public class IDCardAuthenticationService extends AbstractService {

    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    private final IDCardConfigurationProvider configurationProvider;
    private final OCSPValidator ocspValidator;

    public IDCardAuthenticationService(StatisticsHandler statistics,
                                       IDCardConfigurationProvider configurationProvider,
                                       OCSPValidator ocspValidator) {
        super(statistics);
        this.configurationProvider = configurationProvider;
        this.ocspValidator = ocspValidator;
    }

    @Audit(
            action = "ESTEID_AUTHENTICATION",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event loginByIDCard(RequestContext context) {
        SharedAttributeMap<Object> sessionMap = this.getSessionMap(context);
        try {
            X509Certificate certificate = sessionMap.get(Constants.CERTIFICATE_SESSION_ATTRIBUTE, X509Certificate.class);
            if (certificate == null)
                throw new IllegalStateException("Unable to find certificate from session");
            validateUserCert(certificate);

            checkCertStatus(certificate);

            TaraCredential credential = createUserCredential(certificate, context);
            context.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);

            logEvent(StatisticsRecord.builder()
                    .time(LocalDateTime.now())
                    .clientId(getServiceClientId(context))
                    .method(AuthenticationType.IDCard)
                    .operation(SUCCESSFUL_AUTH)
                    .ocsp(getOcspUrlFromMDC())
                    .build()
            );

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);

        } catch (Exception e) {
            logFailureEvent(context, e);
            throw e;
        } finally {
            sessionMap.remove(Constants.CERTIFICATE_SESSION_ATTRIBUTE);
        }
    }

    private void checkCertStatus(X509Certificate certificate) {
        if (this.configurationProvider.isOcspEnabled()) {
            try {
                ocspValidator.checkCert(certificate);
            } catch (OCSPServiceNotAvailableException exception) {
                throw new ExternalServiceHasFailedException(
                        "message.idc.error.ocsp.not.available",
                        "OCSP service is currently not available, please try again later",
                        exception);
            } catch (OCSPValidationException exception) {
                throw new UserAuthenticationFailedException(
                        String.format("message.idc.%s", exception.getStatus().name().toLowerCase()),
                        exception.getMessage(),
                        exception);
            }
        }
    }

    private void validateUserCert(X509Certificate x509Certificate) {
        try {
            x509Certificate.checkValidity();
        } catch (CertificateNotYetValidException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certnotyetvalid",
                    "User certificate is not yet valid", e);
        } catch (CertificateExpiredException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certexpired",
                    "User certificate is expired", e);
        }
    }

    private TaraCredential createUserCredential(X509Certificate userCertificate, RequestContext context) {
        Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(
                userCertificate.getSubjectDN().getName()
        );

        if (isEmailRequested(context)) {
            String email = X509Utils.getRfc822NameSubjectAltName(userCertificate);
            return new IdCardCredential(
                    EstonianIdCodeUtil.getEEPrefixedEstonianIdCode(params.get(CN_SERIALNUMBER)),
                    params.get(CN_GIVEN_NAME),
                    params.get(CN_SURNAME),
                    email
            );
        } else {
            return new IdCardCredential(
                    EstonianIdCodeUtil.getEEPrefixedEstonianIdCode(params.get(CN_SERIALNUMBER)),
                    params.get(CN_GIVEN_NAME),
                    params.get(CN_SURNAME)
            );
        }
    }

    private boolean isEmailRequested(RequestContext context) {
        List<TaraScope > scopes = context.getExternalContext().getSessionMap().get(Constants.TARA_OIDC_SESSION_SCOPES, List.class, null);
        return scopes != null && scopes.contains(TaraScope.EMAIL);
    }

    private String getOcspUrlFromMDC() {
        String ocspUrl = MDC.get(MDC_ATTRIBUTE_OCSP_ID);
        return ocspUrl != null ? ocspUrl : "N/A";
    }

    private void logFailureEvent(RequestContext context, Exception e) {
        logEvent(StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId(getServiceClientId(context))
                .method(AuthenticationType.IDCard)
                .operation(StatisticsOperation.ERROR)
                .ocsp(getOcspUrlFromMDC())
                .error(e.getMessage())
                .build()
        );
    }
}
