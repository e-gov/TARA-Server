package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matchers;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.time.LocalDateTime;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "statistics.tara-stat.enabled=true" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestTaraStatHandler.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class TaraStatHandlerTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private TaraStatHandler taraStatHandler;

    @Before
    public void setUpTest() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void collectWithStartAuthShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final AuthenticationType authenticationType = AuthenticationType.IDCard;
        final StatisticsOperation operationCode = StatisticsOperation.START_AUTH;

        taraStatHandler.collect(time, clientId, authenticationType, operationCode, null);
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"operation\":\"%s\"}",
                time.toString(),
                clientId,
                authenticationType.getAmrName(),
                operationCode.name()
        )));
    }

    @Test
    public void collectWithSuccessfulAuthShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final AuthenticationType authenticationType = AuthenticationType.IDCard;
        final StatisticsOperation operationCode = StatisticsOperation.SUCCESSFUL_AUTH;

        taraStatHandler.collect(time, clientId, authenticationType, operationCode, null);
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"operation\":\"%s\"}",
                time.toString(),
                clientId,
                authenticationType.getAmrName(),
                operationCode.name()
        )));
    }

    @Test
    public void collectWithAuthErrorShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final AuthenticationType authenticationType = AuthenticationType.IDCard;
        final StatisticsOperation operationCode = StatisticsOperation.ERROR;
        final String causeOfError = "Cause of error.";

        taraStatHandler.collect(time, clientId, authenticationType, operationCode, causeOfError);
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"operation\":\"%s\",\"error\":\"%s\"}",
                time.toString(),
                clientId,
                authenticationType.getAmrName(),
                operationCode.name(),
                causeOfError
        )));
    }

}
