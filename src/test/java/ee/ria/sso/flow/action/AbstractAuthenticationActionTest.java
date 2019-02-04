package ee.ria.sso.flow.action;

import ee.ria.sso.AbstractTest;
import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.flow.AuthenticationFlowExecutionException;
import ee.ria.sso.flow.ThymeleafSupport;
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
import java.util.List;

public abstract class AbstractAuthenticationActionTest {

    @Mock
    private ThymeleafSupport thymeleafSupport;

    @Mock
    private TaraResourceBundleMessageSource messageSource;

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
        expectedEx.expect(new ExceptionCodeMatches(401, "error", "Unauthorised authentication method!"));

        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_AUTH_METHOD_RESTRICTED_BY_SCOPE)).thenReturn("Unauthorised authentication method!");
        Mockito.when(thymeleafSupport.isAuthMethodAllowed(Mockito.any())).thenReturn(false);
        getAction().doExecute(requestContext);
    }

    @Test
    public void invalidOriginalUrlInService() throws Exception {
        requestContext.getFlowScope().put(Constants.CAS_SERVICE_ATTRIBUTE_NAME, new AbstractWebApplicationService("id", null, "artifactId") {});
        getAction().doExecute(requestContext);
    }

    @Test
    public void exceptionOccursDuringAuthentication() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(500, "error", "Unexpected exception during authentication action execution"));

        new AbstractAuthenticationAction(messageSource, thymeleafSupport) {

            @Override
            protected Event doAuthenticationExecute(RequestContext requestContext) {
                throw new IllegalStateException("Unexpected exception during authentication action execution");
            }

            @Override
            protected AuthenticationType getAuthenticationType() {
                return AuthenticationType.BankLink;
            }
        }.doExecute(requestContext);
    }

    @Test
    public void exceptionWhenServiceMissingFromFlowContextAndSession() throws Exception {
        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "error", "Session expired"));

        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)).thenReturn("Session expired");

        requestContext.getExternalContext().getSessionMap().remove(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        requestContext.getFlowScope().remove(Constants.CAS_SERVICE_ATTRIBUTE_NAME);

        getAction().doExecute(requestContext);

    }

    @Test
    public void errorWhenValidServicePresentAndUsinCasOauthClientIsMissingCallbackUrl() throws Exception {
        Mockito.when(messageSource.getMessage(Constants.MESSAGE_KEY_SESSION_EXPIRED)).thenReturn("Session expired");

        expectedEx.expect(AuthenticationFlowExecutionException.class);
        expectedEx.expect(new ExceptionCodeMatches(401, "error", "Session expired"));

        requestContext.getExternalContext().getSessionMap().remove(Pac4jConstants.REQUESTED_URL);
        getAction().doExecute(requestContext);
    }


    class ExceptionCodeMatches extends TypeSafeMatcher<AuthenticationFlowExecutionException> {
        private int code;
        private String viewName;
        private String errorMessage;

        public ExceptionCodeMatches(int code, String viewName, String errorMessage) {
            this.code = code;
            this.viewName = viewName;
            this.errorMessage = errorMessage;
        }

        @Override
        protected boolean matchesSafely(AuthenticationFlowExecutionException item) {
            return item.getModelAndView().getStatus().value() == code && item.getModelAndView().getViewName().equals(viewName) && item.getModelAndView().getModel().get(Constants.ERROR_MESSAGE) != null && item.getModelAndView().getModel().get(Constants.ERROR_MESSAGE).equals(errorMessage);
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("expects code: ")
                    .appendValue(code).appendText(" and view: ").appendValue(viewName).appendText(" and msg: ").appendValue(errorMessage);
        }

        @Override
        protected void describeMismatchSafely(AuthenticationFlowExecutionException item, Description mismatchDescription) {
            mismatchDescription.appendText("was code: ")
                    .appendValue(item.getModelAndView().getStatus().value())
                    .appendText(", view name: ")
                    .appendValue(item.getModelAndView().getViewName())
                    .appendText(", msg: ")
                    .appendValue(item.getModelAndView().getModel().containsKey(Constants.ERROR_MESSAGE) ? item.getModelAndView().getModel().get(Constants.ERROR_MESSAGE) : "<missing error message in model!>");
        }
    }

}
