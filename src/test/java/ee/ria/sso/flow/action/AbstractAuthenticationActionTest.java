package ee.ria.sso.flow.action;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.config.cas.CasConfigProperties;
import ee.ria.sso.flow.AuthenticationFlowExecutionException;
import ee.ria.sso.flow.ThymeleafSupport;
import ee.ria.sso.service.ExternalServiceHasFailedException;
import ee.ria.sso.service.UserAuthenticationFailedException;
import org.apereo.cas.authentication.principal.AbstractWebApplicationService;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.pac4j.core.context.Pac4jConstants;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Collections;

import static org.junit.Assert.assertTrue;

public abstract class AbstractAuthenticationActionTest {

    @Mock
    private ThymeleafSupport thymeleafSupport;

    @Mock
    private TaraResourceBundleMessageSource messageSource;

    @Mock
    private CasConfigProperties casConfigProperties;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    RequestContext requestContext;

    abstract AbstractAuthenticationAction getAction();

    @Before
    public void setUp() {
        requestContext = AbstractTest.getRequestContext();
        requestContext.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", "https://cas.server.url/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/response", "artifactId") {});
        requestContext.getExternalContext().getSessionMap().put(Pac4jConstants.REQUESTED_URL, "https://localhost:8451/response");
        requestContext.getExternalContext().getSessionMap().put(Constants.TARA_OIDC_SESSION_AUTH_METHODS, Collections.singletonList(AuthenticationType.SmartID));
        Mockito.when(thymeleafSupport.isAuthMethodAllowed(Mockito.any())).thenReturn(true);
        Mockito.when(casConfigProperties.getServerName()).thenReturn("cas.server");
    }

    @Test
    public void successWhenValidServicePresentButNotUsingCasOauthClient() throws Exception {
        requestContext.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", "https://cas.server.url/cas-management/manage.html", "artifactId") {});
        getAction().doExecute(requestContext);
    }

    @Test
    public void successWhenValidServiceMissingFromFlowContextAndPresentInSession() throws Exception {
        requestContext.getExternalContext().getSessionMap().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", "https://cas.server.url/cas-management/manage.html", "artifactId") {});
        requestContext.getFlowScope().remove(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        requestContext.getExternalContext().getSessionMap().put(Pac4jConstants.REQUESTED_URL, "https://localhost:8451/response");

        getAction().doExecute(requestContext);
    }

    @Test
    public void exceptionWhenAuthenticationMethodNotInAllowedList() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "Unauthorised authentication method!"));

        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_AUTH_METHOD_RESTRICTED_BY_SCOPE)).thenReturn("Unauthorised authentication method!");
        Mockito.when(thymeleafSupport.isAuthMethodAllowed(Mockito.any())).thenReturn(false);

        getAction().doExecute(requestContext);
    }

    @Test
    public void invalidOriginalUrlInService() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        requestContext.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", "", "artifactId") {});
        getAction().doExecute(requestContext);
    }

    @Test
    public void unexpectedExceptionOccursDuringAuthentication() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(500, "mock general error"));

        try {

            Mockito.when(messageSource.getMessage(Mockito.eq(Constants.MESSAGE_KEY_GENERAL_ERROR))).thenReturn("mock general error");
            new AbstractAuthenticationAction(messageSource, thymeleafSupport, casConfigProperties) {

                @Override
                protected Event doAuthenticationExecute(RequestContext requestContext) {
                    throw new IllegalStateException("Unexpected exception during authentication action execution");
                }

                @Override
                protected AuthenticationType getAuthenticationType() {
                    return AuthenticationType.BankLink;
                }
            }.doExecute(requestContext);

        } catch (Exception e){
            assertContextCleared(requestContext);
            throw e;
        }
    }

    @Test
    public void upstreamServiceExceptionOccursDuringAuthentication() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(503, "mock translation"));

        try {
            Mockito.when(messageSource.getMessage(Mockito.eq("msg.key"))).thenReturn("mock translation");
            new AbstractAuthenticationAction(messageSource, thymeleafSupport, casConfigProperties) {

                @Override
                protected Event doAuthenticationExecute(RequestContext requestContext) {
                    throw new ExternalServiceHasFailedException("msg.key", "mock error message");
                }

                @Override
                protected AuthenticationType getAuthenticationType() {
                    return AuthenticationType.BankLink;
                }
            }.doExecute(requestContext);

        } catch (Exception e){
            assertContextCleared(requestContext);
            throw e;
        }
    }

    @Test
    public void authFailedExceptionOccursDuringAuthentication() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "Mock translation"));

        try {
            Mockito.when(messageSource.getMessage(Mockito.eq("msg.key"))).thenReturn("Mock translation");
            new AbstractAuthenticationAction(messageSource, thymeleafSupport, casConfigProperties) {

                @Override
                protected Event doAuthenticationExecute(RequestContext requestContext) {
                    throw new UserAuthenticationFailedException("msg.key", "Error description");
                }

                @Override
                protected AuthenticationType getAuthenticationType() {
                    return AuthenticationType.BankLink;
                }
            }.doExecute(requestContext);

        } catch (Exception e){
            assertContextCleared(requestContext);
            throw e;
        }
    }

    @Test
    public void exceptionWhenServiceMissingFromFlowContextAndSession() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "Session expired"));

        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)).thenReturn("Session expired");

        requestContext.getExternalContext().getSessionMap().remove(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        requestContext.getFlowScope().remove(Constants.CAS_SERVICE_ATTRIBUTE_NAME);

        getAction().doExecute(requestContext);

    }

    @Test
    public void errorWhenValidServicePresentAndUsinCasOauthClientIsMissingCallbackUrl() throws Exception {
        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)).thenReturn("Session expired");

        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "Session expired"));

        requestContext.getExternalContext().getSessionMap().remove(Pac4jConstants.REQUESTED_URL);
        getAction().doExecute(requestContext);
    }

    @Test
    public void exceptionWhenClientNameIsInvalid() throws Exception {
        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_GENERAL_ERROR)).thenReturn("Mock general error");

        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "Mock general error"));
        requestContext.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", "", "artifactId") {});
        getAction().doExecute(requestContext);
    }


    class ExceptionCodeMatches extends TypeSafeMatcher<AuthenticationFlowExecutionException> {
        private int code;
        private String viewName;
        private String errorMessage;

        public ExceptionCodeMatches(int code, String errorMessage) {
            this.code = code;
            this.errorMessage = errorMessage;
        }

        @Override
        protected boolean matchesSafely(AuthenticationFlowExecutionException item) {
            return item.getHttpStatusCode().value() == code && item.getLocalizedMessage() != null && item.getLocalizedMessage().equals(errorMessage);
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("expects code: ")
                    .appendValue(code).appendText(" and view: ").appendValue(viewName).appendText(" and msg: ").appendValue(errorMessage);
        }

        @Override
        protected void describeMismatchSafely(AuthenticationFlowExecutionException item, Description mismatchDescription) {
            mismatchDescription.appendText("was code: ")
                    .appendValue(item.getHttpStatusCode().value())
                    .appendText(", msg: ")
                    .appendValue(item.getLocalizedMessage() != null ? item.getLocalizedMessage() : "<missing error message in model!>");
        }
    }

    private void assertContextCleared(RequestContext requestContext) {
        assertTrue("flow context was not cleared!", requestContext.getFlowScope().isEmpty());
    }
}
