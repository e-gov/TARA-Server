package ee.ria.sso.service.impl;

import java.io.*;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.sso.EidasAuthenticator;
import ee.ria.sso.authentication.EidasAuthenticationFailedException;
import ee.ria.sso.model.AuthenticationResult;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.TaraCredentialsException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.common.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.service.AuthenticationService;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.utils.X509Utils;
import ee.ria.sso.validators.OCSPValidationException;
import ee.ria.sso.validators.OCSPValidator;


/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Service
public class AuthenticationServiceImpl extends AbstractService implements AuthenticationService {

    private final Logger log = LoggerFactory.getLogger(AuthenticationServiceImpl.class);
    private final MobileIDAuthenticatorWrapper mobileIDAuthenticator;
    private final EidasAuthenticator eidasAuthenticator;
    private final Map<String, X509Certificate> issuerCertificates = new HashMap<>();
    private final OCSPValidator ocspValidator;
    private final StatisticsHandler statistics;

    @Value("${mobileID.countryCode:EE}")
    private String midCountryCode;

    @Value("${mobileID.language:EST}")
    private String midLanguage;

    @Value("${mobileID.serviceName:Testimine}")
    private String midServiceName;

    @Value("${mobileID.messageToDisplay:''}")
    private String midMessageToDisplay;

    @Value("${mobileID.serviceUrl:https://tsp.demo.sk.ee}")
    private String midServiceUrl;

    @Value("${ocsp.url:http://demo.sk.ee/ocsp}")
    private String ocspUrl;

    @Value("${ocsp.certificateDirectory:}")
    private String ocspCertDirectory;

    @Value("${ocsp.certificates:}")
    private String ocspCertificates;

    @Value("${ocsp.enabled:false}")
    private boolean ocspEnabled;

    @Value("${eidas.serviceUrl:http://localhost:8889}")
    private String eidasServiceUrl;

    public AuthenticationServiceImpl(TaraResourceBundleMessageSource messageSource,
                                     MobileIDAuthenticatorWrapper mobileIDAuthenticator,
                                     EidasAuthenticator eidasAuthenticator,
                                     OCSPValidator ocspValidator, StatisticsHandler statistics) {
        super(messageSource);
        this.mobileIDAuthenticator = mobileIDAuthenticator;
        this.eidasAuthenticator = eidasAuthenticator;
        this.ocspValidator = ocspValidator;
        this.statistics = statistics;
    }

    @Override
    public Event loginByIDCard(RequestContext context) {
        SharedAttributeMap<Object> map = this.getSessionMap(context);
        try {
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.IDCard, StatisticsOperation.START_AUTH);
            X509Certificate certificate = map.get(Constants.CERTIFICATE_SESSION_ATTRIBUTE, X509Certificate.class);
            Assert.notNull(certificate, "Unable to find certificate from session");
            this.checkCert(certificate);
            Principal subjectDN = certificate.getSubjectDN();
            Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(subjectDN.getName());
            context.getFlowExecutionContext().getActiveSession().getScope()
                .put("credential", new TaraCredential("EE" + params.get("SERIALNUMBER"), params.get("GIVENNAME"), params.get("SURNAME")));
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH);
            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.IDCard, e);
        } finally {
            map.remove(Constants.CERTIFICATE_SESSION_ATTRIBUTE);
        }
    }

    @Override
    public Event startLoginByMobileID(RequestContext context) {
        final TaraCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", TaraCredential.class);
        try {
            if (this.log.isDebugEnabled()) {
                this.log.debug("Starting mobile ID login: <number:{}>, <ssn:{}>", credential.getMobileNumber(), credential.getPrincipalCode());
            }
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.MobileID, StatisticsOperation.START_AUTH);
            this.validateCredential(credential);
            MobileIDSession mobileIDSession = this.mobileIDAuthenticator.startLogin(credential.getPrincipalCode(), this.midCountryCode,
                credential.getMobileNumber());
            if (this.log.isDebugEnabled()) {
                this.log.debug("Login response received ...");
            }
            context.getFlowScope().put(Constants.MOBILE_CHALLENGE, mobileIDSession.challenge);
            context.getFlowScope().put(Constants.MOBILE_NUMBER, credential.getMobileNumber());
            context.getFlowScope().put(Constants.MOBILE_SESSION, mobileIDSession);
            context.getFlowScope().put(Constants.AUTH_COUNT, 0);
            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.MobileID, e);
        }
    }

    @Override
    public Event checkLoginForMobileID(RequestContext context) {
        MobileIDSession session = (MobileIDSession) context.getFlowScope().get(Constants.MOBILE_SESSION);
        int checkCount = context.getFlowScope().get(Constants.AUTH_COUNT, Integer.class);
        String mobileNumber = context.getFlowScope().get(Constants.MOBILE_NUMBER, String.class);
        log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount, session.sessCode);
        try {
            if (this.mobileIDAuthenticator.isLoginComplete(session)) {
                context.getFlowExecutionContext().getActiveSession().getScope().put("credential",
                    new TaraCredential("EE" + session.personalCode, session.firstName, session.lastName, getFormattedPhoneNumber(mobileNumber)));
                this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.MobileID,
                    StatisticsOperation.SUCCESSFUL_AUTH);
                return new Event(this, "success");
            } else {
                context.getFlowScope().put(Constants.AUTH_COUNT, ++checkCount);
                return new Event(this, "outstanding");
            }
        } catch (AuthenticationException e) {
            throw this.handleException(context, AuthenticationType.MobileID, e);
        }
    }

    @Override
    public Event startLoginByEidas(RequestContext context) {
        final TaraCredential credential = context.getFlowExecutionContext().getActiveSession().getScope().get("credential", TaraCredential.class);
        try {
            if (this.log.isDebugEnabled()) {
                this.log.debug("Starting eIDAS login: <country:{}>", credential.getCountry());
            }
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.eIDAS, StatisticsOperation.START_AUTH);

            String relayState = UUID.randomUUID().toString();
            context.getExternalContext().getSessionMap().put(relayState, context.getFlowScope().get("service"));
            String loa = (String) context.getExternalContext().getSessionMap().get("taraAuthorizeRequestAcrValues");
            byte[] authnRequest = this.eidasAuthenticator.authenticate(credential.getCountry(), relayState, loa);
            HttpServletResponse response = (HttpServletResponse) context.getExternalContext().getNativeResponse();
            response.setContentType("text/html; charset=UTF-8");
            OutputStream out = response.getOutputStream();
            out.write(authnRequest);
            out.flush();
            out.close();
            context.getExternalContext().recordResponseComplete();
            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.eIDAS, e);
        }
    }

    @Override
    public Event checkLoginForEidas(RequestContext context) {
        try {
            HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
            String relayState = request.getParameter("RelayState");
            validateRelayState(relayState, context);
            byte[] authResultBytes = this.eidasAuthenticator.getAuthenticationResult(request);
            ObjectMapper jacksonObjectMapper = new ObjectMapper();
            AuthenticationResult authResult = jacksonObjectMapper.readValue(new String(authResultBytes), AuthenticationResult.class);
            TaraCredential credential = new TaraCredential(authResult);
            context.getFlowExecutionContext().getActiveSession().getScope().put("credential",
                    credential);
            context.getFlowScope().put("service", context.getExternalContext().getSessionMap().get(relayState));
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.eIDAS,
                    StatisticsOperation.SUCCESSFUL_AUTH);
            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.eIDAS, e);
        }
    }

    /*
     * RESTRICTED METHODS
     */

    @PostConstruct
    protected void init() {
        initMobileAuthenticator();
        initEidasAuthenticator();
    }

    private void initMobileAuthenticator()  {
        this.mobileIDAuthenticator.setDigidocServiceURL(this.midServiceUrl);
        this.mobileIDAuthenticator.setLanguage(this.midLanguage);
        this.mobileIDAuthenticator.setLoginMessage(this.midMessageToDisplay);
        this.mobileIDAuthenticator.setServiceName(this.midServiceName);
        try {
            if (this.ocspEnabled) {
                Map<String, String> filenameAndCertCNMap =
                        Arrays.stream(this.ocspCertificates.split(",")).map(prop -> prop.split(":"))
                                .collect(
                                        Collectors.toMap(e -> e[0], e -> e[1]));
                for (Map.Entry<String, String> entry : filenameAndCertCNMap.entrySet()) {
                    this.issuerCertificates.put(entry.getKey(), this.readCert(entry.getValue()));
                }
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private void initEidasAuthenticator() {
        this.eidasAuthenticator.setEidasClientUrl(this.eidasServiceUrl);
    }

    private void validateCredential(TaraCredential credential) {
        if (!StringUtils.isNumeric(credential.getPrincipalCode())) {
            throw new TaraCredentialsException("message.mid.invalidcode", credential.getPrincipalCode());
        }
        if (StringUtils.isBlank(credential.getMobileNumber()) || !credential.getMobileNumber().matches("^\\d+$")) {
            throw new TaraCredentialsException("message.mid.invalidnumber", credential.getMobileNumber());
        }
    }

    private RuntimeException handleException(RequestContext context, AuthenticationType type, Exception exception) {
        this.clearScope(context);
        this.statistics.collect(LocalDateTime.now(), context, type, StatisticsOperation.ERROR, exception.getMessage());
        String localizedErrorMessage = null;
        if (exception instanceof TaraCredentialsException) {
            localizedErrorMessage = this.getMessage(((TaraCredentialsException) exception).getKey(), "message.mid.error",
                ((TaraCredentialsException) exception).getValue());
        } else if (exception instanceof AuthenticationException) {
            String messageKey = String.format("message.mid.%s", ((AuthenticationException) exception).getCode().name()
                .toLowerCase().replace("_", ""));
            localizedErrorMessage = this.getMessage(messageKey, "message.mid.error");
        } else if (exception instanceof OCSPValidationException) {
            String messageKey = String.format("message.idc.%s", ((OCSPValidationException) exception).getStatus().name()
                .toLowerCase());
            localizedErrorMessage = this.getMessage(messageKey, "message.idc.error");
        } else if (exception instanceof EidasAuthenticationFailedException) {
            localizedErrorMessage = this.getMessage("message.eidas.authfailed", "message.eidas.error");
        }
        if (StringUtils.isBlank(localizedErrorMessage)) {
            localizedErrorMessage = this.getMessage("message.general.error");
        }
        return new TaraAuthenticationException(localizedErrorMessage, exception);
    }

    private void checkCert(X509Certificate x509Certificate) {
        if (!this.ocspEnabled) {
            return;
        }
        X509Certificate issuerCert = this.findIssuerCertificate(x509Certificate);
        if (issuerCert != null) {
            this.ocspValidator.validate(x509Certificate, issuerCert, this.ocspUrl);
        } else {
            this.log.error("Issuer cert not found");
            throw new RuntimeException("Issuer cert not found from setup");
        }
    }

    private X509Certificate findIssuerCertificate(X509Certificate userCertificate) {
        String issuerCN = X509Utils.getSubjectCNFromCertificate(userCertificate);
        log.debug("IssuerCN extracted: {}", issuerCN);
        return this.issuerCertificates.get(issuerCN);
    }

    private X509Certificate readCert(String filename) throws IOException, CertificateException {
        String fullPath = this.ocspCertDirectory + "/" + filename;
        FileInputStream fis = new FileInputStream(fullPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }

    private void clearScope(RequestContext context) {
        context.getFlowScope().remove(Constants.MOBILE_CHALLENGE);
        context.getFlowScope().remove(Constants.MOBILE_NUMBER);
        context.getFlowScope().remove(Constants.MOBILE_SESSION);
        context.getFlowScope().remove(Constants.AUTH_COUNT);
        context.getFlowScope().remove(TaraCredential.class.getSimpleName());
    }

    private void validateRelayState(String relayState, RequestContext context) {
        if (StringUtils.isEmpty(relayState) || !context.getExternalContext().getSessionMap().contains(relayState)) {
            throw new RuntimeException("SAML response's relay state (" + relayState + ") not found among previously stored relay states!");
        }
    }

    private String getFormattedPhoneNumber(String mobileNumber) {
        if (mobileNumber.startsWith("372")) {
            return "+" + mobileNumber;
        }
        return "+372" + mobileNumber;
    }

}
