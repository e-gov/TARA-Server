package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.service.banklink.BankEnum;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class StatisticsRecordTest {

    private static final String MOCK_CLIENT_ID = "clientId";
    private static final String MOCK_ERROR_DESCRIPTION = "errorDescription";
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");
    private static final String METHOD_BANK_SEPARATOR = "/";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void missingTimeShouldThrowException() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication time cannot be null!");

        StatisticsRecord.builder()
                .time(null)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.IDCard)
                .operation(StatisticsOperation.START_AUTH).build();
    }

    @Test
    public void missingClientIdShouldThrowException() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Client-ID cannot be null!");

        StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId(null)
                .method(AuthenticationType.IDCard)
                .operation(StatisticsOperation.START_AUTH).build();
    }

    @Test
    public void missingMethodShouldThrowException() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication method cannot be null!");

        StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId("client")
                .method((AuthenticationType)null)
                .operation(StatisticsOperation.ERROR).build();
    }

    @Test
    public void missingOperationShouldThrowException() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Statistics operation cannot be null!");

        StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId("client")
                .method(AuthenticationType.eIDAS)
                .operation((StatisticsOperation)null).build();
    }

    @Test
    public void missingBankCodeShouldThrowExceptionWhenMethodBanklink() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Bank cannot be null!");

        StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId("client")
                .method(AuthenticationType.BankLink)
                .operation(StatisticsOperation.START_AUTH).build();
    }

    @Test
    public void missingCountryShouldThrowExceptionWhenMethodEidas() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Country cannot be null!");

        StatisticsRecord.builder()
                .time(LocalDateTime.now())
                .clientId("client")
                .method(AuthenticationType.eIDAS)
                .operation(StatisticsOperation.START_AUTH).build();
    }

    @Test
    public void validTimeAndClientIdAndMethodAndStartAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();
        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.IDCard)
                .operation(StatisticsOperation.START_AUTH).build();
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.IDCard, StatisticsOperation.START_AUTH, null, null);
    }

    @Test
    public void validTimeAndClientIdAndMethodAndSuccessfulAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.IDCard)
                .operation(StatisticsOperation.SUCCESSFUL_AUTH).build();
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH, null, null);
    }

    @Test
    public void validEIDASShouldSucceed() {
        LocalDateTime time = LocalDateTime.now();
        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.eIDAS)
                .country("ee")
                .operation(StatisticsOperation.START_AUTH).build();
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.eIDAS, StatisticsOperation.START_AUTH, null, "EE");
    }

    @Test
    public void validTimeAndClientIdAndBankAndStartAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();
        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.BankLink)
                .bank(BankEnum.SEB.getName())
                .operation(StatisticsOperation.START_AUTH).build();
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, StatisticsOperation.START_AUTH, BankEnum.SEB, null);
    }

    @Test
    public void validTimeAndClientIdAndBankAndSuccessfulAuthOperationShouldSucceed2() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.BankLink)
                .bank(BankEnum.SEB.getName())
                .operation(StatisticsOperation.SUCCESSFUL_AUTH).build();
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, StatisticsOperation.SUCCESSFUL_AUTH, BankEnum.SEB, null);
    }


    @Test
    public void validTimeAndClientIdAndBankAndErrorOperationAndErrorDescriptionShouldSucceed2() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = StatisticsRecord.builder()
                .time(time)
                .clientId(MOCK_CLIENT_ID)
                .method(AuthenticationType.BankLink)
                .bank(BankEnum.SEB.getName())
                .operation(StatisticsOperation.ERROR)
                .error(MOCK_ERROR_DESCRIPTION)
                .build();
        validateErroneousStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, BankEnum.SEB);
    }

    private void validateValidStatisticsRecord(StatisticsRecord statisticsRecord, LocalDateTime time, AuthenticationType method, StatisticsOperation operation, BankEnum bank, String country) {
        Assert.assertNotNull("StatisticsRecord cannot be null!");

        Assert.assertEquals(time.toString(), statisticsRecord.getTime());
        Assert.assertEquals(MOCK_CLIENT_ID, statisticsRecord.getClientId());
        Assert.assertEquals(method.getAmrName(), statisticsRecord.getMethod());
        Assert.assertEquals(operation.name(), statisticsRecord.getOperation());
        Assert.assertEquals(country, statisticsRecord.getCountry());
        Assert.assertNull(statisticsRecord.getError());

        String compoundMethod = method.name();

        if (bank != null) {
            Assert.assertEquals(bank.getName().toUpperCase(), statisticsRecord.getBank());
            compoundMethod += (METHOD_BANK_SEPARATOR + bank.getName().toUpperCase());
        } else if (country != null) {
                Assert.assertEquals(country.toUpperCase(), statisticsRecord.getCountry());
                compoundMethod += (METHOD_BANK_SEPARATOR + country.toUpperCase());
        } else {
            Assert.assertNull(statisticsRecord.getBank());
        }

        Assert.assertEquals(
                String.format("%s;%s;%s;%s;", formatter.format(time), MOCK_CLIENT_ID, compoundMethod, operation.name()),
                statisticsRecord.toString()
        );
    }

    private void validateErroneousStatisticsRecord(StatisticsRecord statisticsRecord, LocalDateTime time, AuthenticationType method, BankEnum bank) {
        Assert.assertNotNull("StatisticsRecord cannot be null!");

        Assert.assertEquals(time.toString(), statisticsRecord.getTime());
        Assert.assertEquals(MOCK_CLIENT_ID, statisticsRecord.getClientId());
        Assert.assertEquals(method.getAmrName(), statisticsRecord.getMethod());
        Assert.assertEquals(StatisticsOperation.ERROR.name(), statisticsRecord.getOperation());
        Assert.assertEquals(MOCK_ERROR_DESCRIPTION, statisticsRecord.getError());

        String compoundMethod = method.name();

        if (bank != null) {
            Assert.assertEquals(bank.getName().toUpperCase(), statisticsRecord.getBank());
            compoundMethod += (METHOD_BANK_SEPARATOR + bank.getName().toUpperCase());
        } else {
            Assert.assertNull(statisticsRecord.getBank());
        }

        Assert.assertEquals(
                String.format("%s;%s;%s;%s;%s", formatter.format(time), MOCK_CLIENT_ID, compoundMethod, StatisticsOperation.ERROR.name(), MOCK_ERROR_DESCRIPTION),
                statisticsRecord.toString()
        );
    }

}
