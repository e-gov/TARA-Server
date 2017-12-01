package ee.ria.sso.service.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import com.google.common.base.Splitter;

import ee.ria.sso.Constants;
import ee.ria.sso.MobileIDAuthenticatorWrapper;
import ee.ria.sso.authentication.IDCardCredential;
import ee.ria.sso.authentication.MobileIDCredential;
import ee.ria.sso.authentication.RiaAuthenticationException;
import ee.ria.sso.model.IDModel;
import ee.ria.sso.service.RiaAuthenticationService;
import ee.ria.sso.utils.X509Utils;
import ee.ria.sso.validators.OCSPValidator;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Service
public class RiaAuthenticationServiceImpl extends AbstractService implements RiaAuthenticationService {

    private static final String MOBILE_CHALLENGE = "mobileChallenge";
    private static final String MOBILE_SESSION = "mobileSession";
    private static final String MOBILE_NUMBER = "mobileNumber";
    private static final String SSN = "principalCode";
    private static final String AUTH_COUNT = "authCount";
    private final Logger log = LoggerFactory.getLogger(RiaAuthenticationServiceImpl.class);
    private final MobileIDAuthenticatorWrapper mobileIDAuthenticator;
    private final Map<String, X509Certificate> issuerCertificates = new HashMap<>();
    private final OCSPValidator ocspValidator;

    @Value("${mobileID.countryCode:EE}")
    private String countryCode;

    @Value("${mobileID.language:EST}")
    private String language;

    @Value("${mobileID.serviceName:Testimine}")
    private String serviceName;

    @Value("${mobileID.messageToDisplay:''}")
    private String messageToDisplay;

    @Value("${mobileID.serviceUrl:https://tsp.demo.sk.ee}")
    private String serviceUrl;

    @Value("${ocsp.url:http://demo.sk.ee/ocsp}")
    private String ocspUrl;

    @Value("${ocsp.certificateDirectory:}")
    private String certDirectory;

    @Value("${ocsp.certificates:}")
    private String certificates;

    @Value("${ocsp.enabled:false}")
    private boolean enabled;

    public RiaAuthenticationServiceImpl(MobileIDAuthenticatorWrapper mobileIDAuthenticator, OCSPValidator ocspValidator,
                                        MessageSource messageSource) {
        super(messageSource);
        this.mobileIDAuthenticator = mobileIDAuthenticator;
        this.ocspValidator = ocspValidator;
    }

    @Override
    public Event loginByIDCard(RequestContext context) {
        SharedAttributeMap<Object> map = this.getSessionMap(context);
        try {
            X509Certificate certificate = map.get(Constants.CERTIFICATE_SESSION_ATTRIBUTE, X509Certificate.class);
            Assert.notNull(certificate, "Unable to find certificate from session");
            this.checkCert(certificate);
            Principal subjectDN = certificate.getSubjectDN();
            Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(subjectDN.getName());
            context.getFlowExecutionContext().getActiveSession().getScope()
                .put("credential",
                    new IDCardCredential(new IDModel(params.get("SERIALNUMBER"), params.get("GIVENNAME"), params.get("SURNAME"))));
            return new Event(this, "success");
        } catch (Exception e) {
            this.handleError(context, e, "Login by ID-card failed");
        } finally {
            map.remove(Constants.CERTIFICATE_SESSION_ATTRIBUTE);
        }
        return null;
    }

    @Override
    public Event startLoginByMobileID(RequestContext context) {
        final String mobileNumber = context.getExternalContext().getRequestParameterMap().get(MOBILE_NUMBER);
        final String socialSecurityCode = context.getExternalContext().getRequestParameterMap().get(SSN);
        Assert.hasLength(mobileNumber, "No mobile number provided");
        Assert.hasLength(socialSecurityCode, "No social security code provided");
        context.getFlowScope().remove("ERROR_CODE");
        if (this.log.isDebugEnabled()) {
            this.log.debug("Starting mobile ID login: <number:{}>, <ssn:{}>", mobileNumber, socialSecurityCode);
        }
        try {
            MobileIDSession mobileIDSession = this.mobileIDAuthenticator.startLogin(socialSecurityCode, this.countryCode, mobileNumber);
            if (this.log.isDebugEnabled()) {
                this.log.debug("Login response received ...");
            }
            context.getFlowScope().put(MOBILE_CHALLENGE, mobileIDSession.challenge);
            context.getFlowScope().put(MOBILE_NUMBER, mobileNumber);
            context.getFlowScope().put(MOBILE_SESSION, mobileIDSession);
            context.getFlowScope().put(AUTH_COUNT, 0);
        } catch (AuthenticationException e) {
            this.handleError(context, e, "Start of Mobile ID login failed");
        }
        return new Event(this, "success");
    }

    @Override
    public Event checkLoginForMobileID(RequestContext context) {
        MobileIDSession session = (MobileIDSession) context.getFlowScope().get(MOBILE_SESSION);
        int checkCount = (int) context.getFlowScope().get(AUTH_COUNT);
        String mobileNumber = (String) context.getFlowScope().get(MOBILE_NUMBER);
        log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount, session.sessCode);
        try {
            if (this.mobileIDAuthenticator.isLoginComplete(session)) {
                context.getFlowExecutionContext().getActiveSession().getScope().put("credential",
                    new MobileIDCredential(session, mobileNumber));
                return new Event(this, "success");
            } else {
                context.getFlowScope().put(AUTH_COUNT, ++checkCount);
                return new Event(this, "outstanding");
            }
        } catch (AuthenticationException e) {
            this.handleError(context, e, "Check of Mobile ID login status failed");
        }
        return null;
    }

    /*
     * RESTRICTED METHODS
     */

    @PostConstruct
    protected void init() {
        this.mobileIDAuthenticator.setDigidocServiceURL(this.serviceUrl);
        this.mobileIDAuthenticator.setLanguage(this.language);
        this.mobileIDAuthenticator.setLoginMessage(this.messageToDisplay);
        this.mobileIDAuthenticator.setServiceName(this.serviceName);
        try {
            if (this.enabled) {
                Map<String, String> filenameAndCertCNMap =
                    Arrays.stream(certificates.split(",")).map(prop -> prop.split(":"))
                        .collect(
                            Collectors.toMap(e -> e[0], e -> e[1]));

                for (Map.Entry<String, String> entry : filenameAndCertCNMap.entrySet()) {
                    this.issuerCertificates.put(entry.getKey(), readCert(entry.getValue()));
                }
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleError(RequestContext context, Exception exception, String error) {
        this.clearSession(context);
        context.getFlowScope().put("SVC_BACK", context.getExternalContext().getSessionMap().get("pac4jRequestedUrl"));
        if (exception instanceof AuthenticationException) {
            throw new RiaAuthenticationException(error, (AuthenticationException) exception);
        }
        throw new RiaAuthenticationException(error, exception);
    }

    private void checkCert(X509Certificate x509Certificate) {
        if (!enabled) {
            return;
        }
        X509Certificate issuerCert = findIssuerCertificate(x509Certificate);
        if (issuerCert != null) {
            boolean result = ocspValidator
                .isCertiticateValid(x509Certificate, issuerCert,
                    ocspUrl);
            if (!result) {
                log.error("Could not verify client certificate validity");
                throw new RuntimeException("Could not verify client certificate validity");
            }
        } else {
            log.error("Issuer cert not found");
            throw new RuntimeException("Issuer cert not found from setup");
        }
    }

    private X509Certificate findIssuerCertificate(X509Certificate userCertificate) {
        String issuerCN = X509Utils.getSubjectCNFromCertificate(userCertificate);
        log.debug("IssuerCN extracted: {}", issuerCN);
        return issuerCertificates.get(issuerCN);
    }

    private X509Certificate readCert(String filename) throws IOException, CertificateException {
        String fullPath = certDirectory + "/" + filename;
        FileInputStream fis = new FileInputStream(fullPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }

    private void clearSession(RequestContext context) {
        context.getFlowScope().remove(MOBILE_CHALLENGE);
        context.getFlowScope().remove(MOBILE_NUMBER);
        context.getFlowScope().remove(MOBILE_SESSION);
        context.getFlowScope().remove(AUTH_COUNT);
        context.getFlowScope().remove(MobileIDCredential.class.getSimpleName());
        context.getFlowScope().remove(IDCardCredential.class.getSimpleName());
    }

}
