package ee.ria.sso.service;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecordMatcher;
import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockFlowExecutionContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.time.LocalDateTime;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
public abstract class AbstractAuthenticationServiceTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    protected StatisticsHandler statisticsHandler;

    @Autowired
    protected Environment environment;

    protected MockRequestContext getMockRequestContext() {
        MockRequestContext context = new MockRequestContext();

        MockExternalContext mockExternalContext = new MockExternalContext();
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter(Constants.CAS_SERVICE_ATTRIBUTE_NAME,
                "https://cas.test.url.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response");
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
        mockExternalContext.getSessionMap().put(Constants.TARA_OIDC_SESSION_CLIENT_ID, "openIdDemo");
        context.setExternalContext(mockExternalContext);
        context.setFlowExecutionContext(new MockFlowExecutionContext());
        return context;
    }

    protected MockRequestContext getMockRequestContext(Map<String, String> requestParameters) {
        MockRequestContext context = getMockRequestContext();

        if (requestParameters != null) {
            MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
            requestParameters.forEach((k, v) -> map.put(k, v));
        }

        return context;
    }

    protected void assertStatisticsEventCollected(StatisticsOperation status, AuthenticationType type) {
        verify(statisticsHandler, times(1)).collect(argThat(
                new StatisticsRecordMatcher(
                        Matchers.any(LocalDateTime.class),
                        Matchers.equalTo("openIdDemo"),
                        Matchers.equalTo(type),
                        Matchers.equalTo(status),
                        Matchers.nullValue(String.class),
                        Matchers.nullValue(String.class)
                )
        ));
    }

    protected void assertErrorStatisticsCollected(String exceptionMessage, AuthenticationType type) {
        verify(statisticsHandler, times(1)).collect(argThat(
                new StatisticsRecordMatcher(
                        Matchers.any(LocalDateTime.class),
                        Matchers.equalTo("openIdDemo"),
                        Matchers.equalTo(type),
                        Matchers.equalTo(StatisticsOperation.ERROR),
                        exceptionMessage == null ? Matchers.isEmptyOrNullString() : Matchers.equalTo(exceptionMessage),
                        Matchers.nullValue(String.class)
                )
        ));
    }

    protected void assertAuthStatisticsNotCollected() {
        verify(statisticsHandler, never()).collect(any());
    }
}
