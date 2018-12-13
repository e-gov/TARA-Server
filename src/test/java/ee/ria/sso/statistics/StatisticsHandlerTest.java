package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.test.SimpleTestAppender;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.hamcrest.Matchers.containsString;

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
    public void collectShouldFailWhenStatisticsRecordMissing() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("StatisticsRecord cannot be null!");

        new StatisticsHandler().collect(null);
    }

    @Test
    public void collectShouldSucceedWithAuthenticationOperations() {
        assertMessageLogged("clientId", AuthenticationType.IDCard, StatisticsOperation.START_AUTH, String.format(
                "%s;%s;%s;%s;", LOG_DATE_TIME_FORMATTER.format(FIXED_TIME), "clientId", AuthenticationType.IDCard.name(), StatisticsOperation.START_AUTH.name()
        ));
        assertMessageLogged("clientId", AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH, String.format(
                "%s;%s;%s;%s;", LOG_DATE_TIME_FORMATTER.format(FIXED_TIME), "clientId", AuthenticationType.IDCard.name(), StatisticsOperation.SUCCESSFUL_AUTH.name()
        ));
    }

    private void assertMessageLogged(String clientId, AuthenticationType authenticationType, StatisticsOperation operation, String expectedMessage) {
        SimpleTestAppender.events.clear();
        new StatisticsHandler().collect(new StatisticsRecord(FIXED_TIME, clientId, authenticationType, operation));
        SimpleTestAppender.verifyLogEventsExistInOrder(containsString(expectedMessage));
    }

    @Test
    public void collectShouldSucceedWithErrorOperation() {
        assertErrorLogged("clientId", AuthenticationType.IDCard, "Error message!", String.format(
                "%s;%s;%s;%s;%s", LOG_DATE_TIME_FORMATTER.format(FIXED_TIME), "clientId", AuthenticationType.IDCard.name(), StatisticsOperation.ERROR.name(), "Error message!"
        ));
    }

    private void assertErrorLogged(String clientId, AuthenticationType authenticationType, String errorMessage, String expectedMessage) {
        SimpleTestAppender.events.clear();
        new StatisticsHandler().collect(new StatisticsRecord(FIXED_TIME, clientId, authenticationType, errorMessage));
        SimpleTestAppender.verifyLogEventsExistInOrder(containsString(expectedMessage));
    }

}
