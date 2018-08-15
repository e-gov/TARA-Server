package ee.ria.sso.service.smartid;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
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

    public static TaraCredential mockCredential() {
        return mockCredential(VALID_EE_PERSON_IDENTIFIER);
    }

    public static TaraCredential mockCredential(String personIdentifier) {
        TaraCredential credential = new TaraCredential();
        credential.setCountry("EE");
        credential.setPrincipalCode(personIdentifier);
        return credential;
    }

    public static MockRequestContext mockAuthInitRequestContext(TaraCredential credential) {
        MockRequestContext requestContext = new MockRequestContext();
        setMockContextExternalContext(requestContext);
        requestContext.getFlowExecutionContext().getActiveSession().getScope().put(Constants.CREDENTIAL, credential);
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
                "https://cas.test.url.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=clientId&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response");
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
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
        sessionStatus.setCertificate(sessionCertificate);

        SessionSignature sessionSignature = new SessionSignature();
        sessionSignature.setAlgorithm("sha512WithRSAEncryption");
        sessionSignature.setValueInBase64(AUTH_HASH_SIGNATURE_IN_BASE64);
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
