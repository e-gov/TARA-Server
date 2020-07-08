package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockRequestContext;

public class SmartIDMockData {

    public static final String VALID_EE_PERSON_IDENTIFIER = "47101010033";
    public static final String SMART_ID_TEST_CERTIFICATE = "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";
    public static final String EXPIRED_AUTH_CERTIFICATE = "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";

    public static final String AUTH_HASH_IN_BASE64 = "Mn5DrFjrrHzFOniG0B7K8sLVunVtEuM7BgO23QtSVfVw66h37u/lB2rQKFPzhsWSMxdaeMX2Z0A7p154fkK/Fg==";
    public static final String AUTH_HASH_SIGNATURE_IN_BASE64 = "EAIflnT/7NU+oBQp9tkuhpAWWxtyvhXI91379oqP3RYZVajOIWzd2rxuYhZixijotjacwwJGsrGd0+Is0aD88+dz8DuVFbYOjjehuO9CXFc3P9ZMKcg0YcKBDKfTCrI6hoD/dIoNhRXMSSWIOa87cd2H+1IQyDHDqNfxKC2u+e3yPUZVaaTLixacq5dLs8w+DIOdaSbcVpCjQqoH7NMAg5I0QgC8fQ5FGNCmKfUKYZirOzo1l78JttHs9YRN1/3F1NQcTWZhMf9e7+NEu8ebPQR80NAdGhQ9FybnxosG/Ll9WUykfi3GPFvsYGipS2NZJon4yEisqaSN6q7dVtL6z4eRJmyPK3zlk02XP2oPz+wKgg6MlDCCtOeTkZLxLWFXofARDTdsqhlBtvMZhJhaqCh/8HJdCIDcrWVbuvB2OAUMge6HR8gx87hrrRSAtA7aOjGHwhwdJjJN51dU/sjSEkbTpqVplTbjkg4aBj66eJWzLeIJU3nVEczKinQiFyrUUuI+bUxFbGCLnur7AEJv2PnmoEA/lA7B51wByt5l1GRptEPu+vNsIRBB6SXeBU0YiCovOqDQ4XdaWaTKi5zy3pDYHLqOT5KDjjMGT0k7tjBKpNtGuAzCfBlwVe6NIIORKNRvx8guYlC+ef/e7SVJD+NEPYgwAvKPG9nvLj6FsUE=";

    public static final String INVALID_SIGNATURE_IN_BASE64 = "XDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

    public static PreAuthenticationCredential mockCredential() {
        return mockCredential(VALID_EE_PERSON_IDENTIFIER);
    }

    public static PreAuthenticationCredential mockCredential(String personIdentifier) {
        PreAuthenticationCredential credential = new PreAuthenticationCredential();
        credential.setCountry("EE");
        credential.setPrincipalCode(personIdentifier);
        return credential;
    }

    public static MockRequestContext mockAuthInitRequestContext(PreAuthenticationCredential credential) {
        MockRequestContext requestContext = new MockRequestContext();
        setMockContextExternalContext(requestContext);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);
        return requestContext;
    }

    public static MockRequestContext mockSessionStatusRequestContext(AuthenticationHash authHash, String sessionId, int sessionStatusCheckCount) {
        AuthenticationSession authSessionMock = AuthenticationSession.builder()
                .sessionId(sessionId)
                .authenticationHash(authHash)
                .certificateLevel(SmartIDAuthenticationService.DEFAULT_CERTIFICATE_LEVEL)
                .statusCheckCount(sessionStatusCheckCount)
                .build();

        MockRequestContext requestContext = new MockRequestContext();
        setMockContextExternalContext(requestContext);
        requestContext.getFlowScope().put(Constants.SMART_ID_VERIFICATION_CODE, authHash.calculateVerificationCode());
        requestContext.getFlowScope().put(Constants.SMART_ID_AUTHENTICATION_SESSION, authSessionMock);
        return requestContext;
    }

    private static void setMockContextExternalContext(MockRequestContext requestContext) {
        MockExternalContext mockExternalContext = new MockExternalContext();
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter(Constants.CAS_SERVICE_ATTRIBUTE_NAME,
                "https://cas.test.url.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response");
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
        mockExternalContext.getSessionMap().put(Constants.TARA_OIDC_SESSION_CLIENT_ID, "openIdDemo");
        requestContext.setExternalContext(mockExternalContext);
    }
    
    public static SessionStatus mockRunningSessionStatus() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setState(SessionState.RUNNING.name());
        return sessionStatus;
    }

    public static SessionStatus mockCompleteSessionStatus(SessionEndResult endResult) {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setState(SessionState.COMPLETE.name());

        SessionResult sessionResult = new SessionResult();
        sessionResult.setDocumentNumber("doc-number");
        sessionResult.setEndResult(endResult == null ? null : endResult.name());
        sessionStatus.setResult(sessionResult);

        SessionCertificate sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel(CertificateLevel.QUALIFIED.name());
        sessionCertificate.setValue(SMART_ID_TEST_CERTIFICATE);
        sessionStatus.setCert(sessionCertificate);

        SessionSignature sessionSignature = new SessionSignature();
        sessionSignature.setAlgorithm("sha512WithRSAEncryption");
        sessionSignature.setValue(AUTH_HASH_SIGNATURE_IN_BASE64);
        sessionStatus.setSignature(sessionSignature);
        return sessionStatus;
    }

    public static SmartIdAuthenticationResult mockAuthenticationResult(String personIdentifier, String country) {
        SmartIdAuthenticationResult authResult = new SmartIdAuthenticationResult();
        authResult.setValid(true);
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setIdentityCode(personIdentifier);
        authenticationIdentity.setCountry(country);
        authenticationIdentity.setGivenName("GIVENNAME-" + personIdentifier);
        authenticationIdentity.setSurName("SURNAME-" + personIdentifier);
        authResult.setAuthenticationIdentity(authenticationIdentity);
        return authResult;
    }

    public static AuthenticationHash mockAuthenticationHash() {
        AuthenticationHash authHash = new AuthenticationHash();
        authHash.setHashInBase64(AUTH_HASH_IN_BASE64);
        authHash.setHashType(HashType.SHA512);
        return authHash;
    }
}
