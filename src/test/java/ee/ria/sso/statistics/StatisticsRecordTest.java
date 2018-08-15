package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.BankEnum;
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
    public void missingTimeShouldThrowException1() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication time cannot be null!");

        new StatisticsRecord(null, MOCK_CLIENT_ID, AuthenticationType.IDCard, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingTimeShouldThrowException2() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication time cannot be null!");

        new StatisticsRecord(null, MOCK_CLIENT_ID, AuthenticationType.IDCard, MOCK_ERROR_DESCRIPTION);
    }

    @Test
    public void missingTimeShouldThrowException3() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication time cannot be null!");

        new StatisticsRecord(null, MOCK_CLIENT_ID, BankEnum.SEB, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingTimeShouldThrowException4() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication time cannot be null!");

        new StatisticsRecord(null, MOCK_CLIENT_ID, BankEnum.SEB, MOCK_ERROR_DESCRIPTION);
    }


    @Test
    public void missingClientIdShouldThrowException1() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Client-ID cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), null, AuthenticationType.IDCard, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingClientIdShouldThrowException2() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Client-ID cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), null, AuthenticationType.IDCard, MOCK_ERROR_DESCRIPTION);
    }

    @Test
    public void missingClientIdShouldThrowException3() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Client-ID cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), null, BankEnum.SEB, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingClientIdShouldThrowException4() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Client-ID cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), null, BankEnum.SEB, MOCK_ERROR_DESCRIPTION);
    }


    @Test
    public void missingMethodShouldThrowException1() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication method cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, (AuthenticationType) null, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingMethodShouldThrowException2() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Authentication method cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, (AuthenticationType) null, MOCK_ERROR_DESCRIPTION);
    }


    @Test
    public void missingOperationShouldThrowException1() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Statistics operation cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, AuthenticationType.IDCard, (StatisticsOperation) null);
    }

    @Test
    public void missingOperationShouldThrowException2() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Statistics operation cannot be null!");

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, BankEnum.SEB, (StatisticsOperation) null);
    }


    @Test
    public void missingErrorDescriptionShouldSucceedOnErrorOperation2() {
        StatisticsRecord statisticsRecord = new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, AuthenticationType.IDCard, (String) null);
        Assert.assertEquals("", statisticsRecord.getError());
    }

    @Test
    public void missingErrorDescriptionShouldSucceedOnErrorOperation4() {
        StatisticsRecord statisticsRecord = new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, BankEnum.SEB, (String) null);
        Assert.assertEquals("", statisticsRecord.getError());
    }


    @Test
    public void missingBankShouldThrowExceptionOnBanklinkMethod3() {
        expectedEx.expect(NullPointerException.class);

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, (BankEnum) null, StatisticsOperation.START_AUTH);
    }

    @Test
    public void missingBankShouldThrowExceptionOnBanklinkMethod4() {
        expectedEx.expect(NullPointerException.class);

        new StatisticsRecord(LocalDateTime.now(), MOCK_CLIENT_ID, (BankEnum) null, MOCK_ERROR_DESCRIPTION);
    }


    @Test
    public void validTimeAndClientIdAndMethodAndStartAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, AuthenticationType.IDCard, StatisticsOperation.START_AUTH);
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.IDCard, StatisticsOperation.START_AUTH, null);
    }

    @Test
    public void validTimeAndClientIdAndMethodAndSuccessfulAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH);
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.IDCard, StatisticsOperation.SUCCESSFUL_AUTH, null);
    }

    @Test
    public void validTimeAndClientIdAndMethodAndErrorOperationAndErrorDescriptionShouldSucceed2() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, AuthenticationType.IDCard, MOCK_ERROR_DESCRIPTION);
        validateErroneousStatisticsRecord(statisticsRecord, time, AuthenticationType.IDCard, null);
    }

    @Test
    public void validTimeAndClientIdAndBankAndStartAuthOperationShouldSucceed1() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, BankEnum.SEB, StatisticsOperation.START_AUTH);
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, StatisticsOperation.START_AUTH, BankEnum.SEB);
    }

    @Test
    public void validTimeAndClientIdAndBankAndSuccessfulAuthOperationShouldSucceed2() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, BankEnum.SEB, StatisticsOperation.SUCCESSFUL_AUTH);
        validateValidStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, StatisticsOperation.SUCCESSFUL_AUTH, BankEnum.SEB);
    }


    @Test
    public void validTimeAndClientIdAndBankAndErrorOperationAndErrorDescriptionShouldSucceed2() {
        LocalDateTime time = LocalDateTime.now();

        StatisticsRecord statisticsRecord = new StatisticsRecord(time, MOCK_CLIENT_ID, BankEnum.SEB, MOCK_ERROR_DESCRIPTION);
        validateErroneousStatisticsRecord(statisticsRecord, time, AuthenticationType.BankLink, BankEnum.SEB);
    }


    private void validateValidStatisticsRecord(StatisticsRecord statisticsRecord, LocalDateTime time, AuthenticationType method, StatisticsOperation operation, BankEnum bank) {
        Assert.assertNotNull("StatisticsRecord cannot be null!");

        Assert.assertEquals(time.toString(), statisticsRecord.getTime());
        Assert.assertEquals(MOCK_CLIENT_ID, statisticsRecord.getClientId());
        Assert.assertEquals(method.getAmrName(), statisticsRecord.getMethod());
        Assert.assertEquals(operation.name(), statisticsRecord.getOperation());
        Assert.assertNull(statisticsRecord.getError());

        String compoundMethod = method.name();

        if (bank != null) {
            Assert.assertEquals(bank.getName().toUpperCase(), statisticsRecord.getBank());
            compoundMethod += (METHOD_BANK_SEPARATOR + bank.getName().toUpperCase());
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
