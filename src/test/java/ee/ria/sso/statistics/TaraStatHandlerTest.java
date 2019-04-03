package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.banklink.BankEnum;
import ee.ria.sso.test.SimpleTestAppender;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
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
    public void collectWithMissingStatisticsRecordShouldFail() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("StatisticsRecord cannot be null!");

        taraStatHandler.collect(null);
    }

    @Test
    public void collectWithStartAuthShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final AuthenticationType authenticationType = AuthenticationType.IDCard;
        final StatisticsOperation operationCode = StatisticsOperation.START_AUTH;

        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(authenticationType)
                .operation(operationCode)
                .build());
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

        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(authenticationType)
                .operation(operationCode)
                .build());
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

        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(authenticationType)
                .operation(operationCode)
                .error(causeOfError)
                .build());
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"operation\":\"%s\",\"error\":\"%s\"}",
                time.toString(),
                clientId,
                authenticationType.getAmrName(),
                operationCode.name(),
                causeOfError
        )));
    }

    @Test
    public void collectWithStartAuthAndBankShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final StatisticsOperation operationCode = StatisticsOperation.START_AUTH;
        final BankEnum bank = BankEnum.SEB;

        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(AuthenticationType.BankLink)
                .bank(bank.getName())
                .operation(operationCode)
                .build());
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"bank\":\"%s\",\"operation\":\"%s\"}",
                time.toString(),
                clientId,
                AuthenticationType.BankLink.getAmrName(),
                bank.getName().toUpperCase(),
                operationCode.name()
        )));
    }

    @Test
    public void collectWithSuccessfulAuthAndBankShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final StatisticsOperation operationCode = StatisticsOperation.SUCCESSFUL_AUTH;
        final BankEnum bank = BankEnum.SEB;

        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(AuthenticationType.BankLink)
                .bank(bank.getName())
                .operation(operationCode)
                .build());
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"bank\":\"%s\",\"operation\":\"%s\"}",
                time.toString(),
                clientId,
                AuthenticationType.BankLink.getAmrName(),
                bank.getName().toUpperCase(),
                operationCode.name()
        )));
    }

    @Test
    public void collectWithAuthErrorAndBankShouldSucceed() {
        final LocalDateTime time = LocalDateTime.now();
        final String clientId = "clientIdString";
        final StatisticsOperation operationCode = StatisticsOperation.ERROR;
        final String causeOfError = "Cause of error.";
        final BankEnum bank = BankEnum.SEB;
        taraStatHandler.collect(StatisticsRecord.builder()
                .time(time)
                .clientId(clientId)
                .method(AuthenticationType.BankLink)
                .bank(bank.getName())
                .operation(operationCode)
                .error(causeOfError)
                .build());
        SimpleTestAppender.verifyLogEventsExistInOrder(Matchers.containsString(String.format(
                "{\"time\":\"%s\",\"clientId\":\"%s\",\"method\":\"%s\",\"bank\":\"%s\",\"operation\":\"%s\",\"error\":\"%s\"}",
                time.toString(),
                clientId,
                AuthenticationType.BankLink.getAmrName(),
                bank.getName().toUpperCase(),
                operationCode.name(),
                causeOfError
        )));
    }

}
