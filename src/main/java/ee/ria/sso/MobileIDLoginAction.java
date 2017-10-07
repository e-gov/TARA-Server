package ee.ria.sso;


import java.io.ByteArrayInputStream;
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
import javax.servlet.http.HttpServletRequest;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDSession;
import com.google.common.base.Splitter;
import org.apache.axis.encoding.Base64;
import org.apache.axis.utils.StringUtils;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.model.IDModel;


/**
 * Created by serkp on 7.09.2017.
 */
@Component("mobileIDLoginAction")
public class MobileIDLoginAction {
    private static final Logger log = LoggerFactory.getLogger(MobileIDLoginAction.class);

    private static final String SSL_CLIENT_CERT = "SSL_CLIENT_CERT";
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    private static final String MOBILE_CHALLENGE = "mobileChallenge";
    private static final String MOBILE_SESSION = "mobileSession";
    private static final String MOBILE_NUMBER = "mobileNumber";
    private static final String AUTH_COUNT = "authCount";

    private final MIDAuthenticator mIDAuthenticator;
    private final Map<String, X509Certificate> isseurCertificates = new HashMap<>();
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

    @Value("${ocsp.enabled}")
    private boolean enabled;

    @Autowired
    public MobileIDLoginAction(@Qualifier("MIDAuthenticator") MIDAuthenticator mIDAuthenticator,
                               @Qualifier("ocspValidator") OCSPValidator ocspValidator) {
        this.mIDAuthenticator = mIDAuthenticator;
        this.ocspValidator = ocspValidator;
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
        return isseurCertificates.get(issuerCN);
    }

    private X509Certificate readCert(String filename) throws IOException, CertificateException {
        String fullPath = certDirectory + "/" + filename;

        FileInputStream fis = new FileInputStream(fullPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();

        return cert;
    }

    public Event idsubmit(RequestContext context) {
        try {
            final HttpServletRequest request = WebUtils.getHttpServletRequest(context);
            String certStr = request.getHeader(SSL_CLIENT_CERT);
            if (StringUtils.isEmpty(certStr)) {
                return null;
            }
            byte[] decoded = Base64
                    .decode(certStr.replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""));
            X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                                                                       .generateCertificate(
                                                                               new ByteArrayInputStream(
                                                                                       decoded));

            checkCert(x509);

            Principal subjectDN = x509.getSubjectDN();
            Map<String, String> params = Splitter
                    .on(", ")
                    .withKeyValueSeparator("=")
                    .split(subjectDN.getName());

            context.getFlowExecutionContext()
                   .getActiveSession()
                   .getScope()
                   .put("credential",
                        new UsernamePasswordCredential(params.get("SERIALNUMBER"),
                                                       new IDModel(params.get
                                                               ("SERIALNUMBER"),
                                                                   params.get
                                                                           ("GIVENNAME"),
                                                                   params.get(
                                                                           "SURNAME")
                                                       )));
            return new Event(this, "success");
        } catch (Exception e) {
            log.error("ID Login check failed. Msg={}", e);
            clearSession(context);
            throw new RuntimeException("ID_ERRROR");
        }
    }

    public Event submit(RequestContext context) {
        final String mobileNumber =
                context.getExternalContext().getRequestParameterMap().get("mobileNumber");

        final String personalCode =
                context.getExternalContext().getRequestParameterMap().get("principalCode");

        if (mobileNumber == null || personalCode == null || mobileNumber.trim().length() == 0
                || personalCode.trim().length() == 0) {
            log.warn(
                    "Authentication attemp with empty principalCode or mobileNumber. Forbidden");
            throw new RuntimeException("MID_ERRROR");
        }

        context.getFlowScope().remove("ERROR_CODE");
        log.info("Starting mobile ID login with numbers {} {}", mobileNumber, personalCode);

        try {
            MobileIDSession mIDSession =
                    mIDAuthenticator.startLogin(personalCode, countryCode, mobileNumber);
            log.info("Login response: {}", mIDSession);

            context.getFlowScope().put(MOBILE_CHALLENGE, mIDSession.challenge);
            context.getFlowScope().put(MOBILE_NUMBER, mobileNumber);
            context.getFlowScope().put(MOBILE_SESSION, mIDSession);
            context.getFlowScope().put(AUTH_COUNT, 0);

        } catch (AuthenticationException ex) {
            log.error("Mid Login start failed. Msg={}", ex.getMessage());
            clearSession(context);
            throw new RuntimeException("MID_ERRROR");
        }

        return new Event(this, "success");
    }

    public Event check(RequestContext context) {
        MobileIDSession session = (MobileIDSession) context.getFlowScope().get(MOBILE_SESSION);
        int checkCount = (int) context.getFlowScope().get(AUTH_COUNT);
        String mobileNumber = (String) context.getFlowScope().get(MOBILE_NUMBER);

        log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount,
                  session.sessCode);

        try {
            boolean isLoginComplete = mIDAuthenticator.isLoginComplete(session);

            if (isLoginComplete) {
                context.getFlowExecutionContext()
                       .getActiveSession()
                       .getScope()
                       .put("credential", new UsernamePasswordCredential(mobileNumber, session));
                return new Event(this, "success");
            } else {
                context.getFlowScope().put(AUTH_COUNT, ++checkCount);
                return new Event(this, "outstanding");
            }
        } catch (AuthenticationException ex) {
            log.error("Mid Login check failed. Msg={}", ex.getMessage());
            clearSession(context);
            throw new RuntimeException("MID_ERRROR");
        }
    }

    @PostConstruct
    public void init() {
        mIDAuthenticator.setDigidocServiceURL(serviceUrl);
        mIDAuthenticator.setLanguage(language);
        mIDAuthenticator.setLoginMessage(messageToDisplay);
        mIDAuthenticator.setServiceName(serviceName);
        try {
            if (enabled) {
                Map<String, String> filenameAndCertCNMap =
                        Arrays.stream(certificates.split(",")).map(prop -> prop.split(":"))
                              .collect(
                                      Collectors.toMap(e -> e[0], e -> e[1]));

                for (Map.Entry<String, String> entry : filenameAndCertCNMap.entrySet()) {

                    isseurCertificates.put(entry.getKey(), readCert(entry.getValue()));
                }
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private void clearSession(RequestContext context) {
        context.getFlowScope().remove(MOBILE_CHALLENGE);
        context.getFlowScope().remove(UsernamePasswordCredential.class.getSimpleName());
        context.getFlowScope().remove(MOBILE_NUMBER);
        context.getFlowScope().remove(MOBILE_SESSION);
        context.getFlowScope().remove(AUTH_COUNT);
    }
}
