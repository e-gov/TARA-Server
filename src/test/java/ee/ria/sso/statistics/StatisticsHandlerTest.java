package ee.ria.sso.statistics;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.test.SimpleTestAppender;

import org.apereo.cas.authentication.principal.AbstractWebApplicationService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

public class StatisticsHandlerTest {

    public static final LocalDateTime FIXED_TIME = LocalDateTime.of(2001, 12, 31, 01, 59, 59);
    public static final DateTimeFormatter LOG_DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");
    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setUpTest() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void missingRequestContext() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("RequestContext cannot be null!");

        StatisticsHandler statisticsHandler = new StatisticsHandler();
        statisticsHandler.collect(FIXED_TIME, null, AuthenticationType.BankLink, StatisticsOperation.SUCCESSFUL_AUTH);
    }

    @Test
    public void malformedServiceUrl() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        ((MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest()).addParameter("service", "invalidUrl");

        new StatisticsHandler().collect(FIXED_TIME, requestContext, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH);
        assertMessagesNotLogged(requestContext, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH);
    }

    @Test
    public void successfulLoggingWhenServiceAndClientIdProvidedInRequest() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        ((MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest()).addParameter("service", "https://some.cas.url.for.testing.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.unit.test:8451/oauth/response");

        for (AuthenticationType authType : AuthenticationType.values()) {
            assertMessageLogged(requestContext, authType, StatisticsOperation.SUCCESSFUL_AUTH, FIXED_TIME.format(LOG_DATE_TIME_FORMATTER) + ";openIdDemo;" + authType.name() + ";" + StatisticsOperation.SUCCESSFUL_AUTH.name() + ";");
            assertMessageLogged(requestContext, authType, StatisticsOperation.START_AUTH, FIXED_TIME.format(LOG_DATE_TIME_FORMATTER)  + ";openIdDemo;" + authType.name() + ";" + StatisticsOperation.START_AUTH.name() + ";");
        }
    }

    @Test
    public void successfulLoggingWhenServiceAndClientIdProvidedInFlowScope() {

        RequestContext requestContext = getMockRequestContext(new HashMap<>());
        requestContext.getFlowScope().put("service", new AbstractWebApplicationService("", "https://some.cas.url.for.testing.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.unit.test:8451/oauth/response", "") {});

        for (AuthenticationType authType : AuthenticationType.values()) {
            assertMessageLogged(requestContext, authType, StatisticsOperation.SUCCESSFUL_AUTH, FIXED_TIME.format(LOG_DATE_TIME_FORMATTER) + ";openIdDemo;" + authType.name() + ";" + StatisticsOperation.SUCCESSFUL_AUTH.name() + ";");
            assertMessageLogged(requestContext, authType, StatisticsOperation.START_AUTH, FIXED_TIME.format(LOG_DATE_TIME_FORMATTER) + ";openIdDemo;" + authType.name() + ";" + StatisticsOperation.START_AUTH.name() + ";");
        }
    }

    @Test
    public void clientIdNotFoundInRequestAndInFlowScope() {
        RequestContext requestContext = getMockRequestContext(new HashMap<>());

        for (AuthenticationType authType : AuthenticationType.values()) {
            assertMessagesNotLogged(requestContext, authType, StatisticsOperation.SUCCESSFUL_AUTH);
            assertMessagesNotLogged(requestContext, authType, StatisticsOperation.START_AUTH);
        }
    }

    private void assertMessageLogged(RequestContext requestContext, AuthenticationType authenticationType, StatisticsOperation operation, String expectedMessage) {
        SimpleTestAppender.events.clear();
        new StatisticsHandler().collect(FIXED_TIME, requestContext, authenticationType, operation);
        SimpleTestAppender.verifyLogEventsExistInOrder(
                not(containsString(TaraStatHandler.class.getCanonicalName())),
                0, containsString(expectedMessage));
    }

    private void assertMessagesNotLogged(RequestContext requestContext, AuthenticationType authenticationType, StatisticsOperation operation) {
        SimpleTestAppender.events.clear();
        new StatisticsHandler().collect(FIXED_TIME, requestContext, authenticationType, operation);
        Assert.assertTrue("Log messages found, when none expected! " + SimpleTestAppender.events, SimpleTestAppender.events.isEmpty());
    }

    private RequestContext getMockRequestContext(Map<String, String> parameters) {
        MockRequestContext context = new MockRequestContext();

        MockExternalContext mockExternalContext = new MockExternalContext();
        mockExternalContext.setNativeRequest(new MockHttpServletRequest());
        context.setExternalContext(mockExternalContext);

        MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
        parameters.forEach((k, v) ->
                map.put(k, v)
        );

        return context;
    }
}
