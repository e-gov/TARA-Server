package ee.ria.sso.statistics;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.BankEnum;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"time","clientId","method","bank","operation","error"})
public class StatisticsRecord {

    public static final String METHOD_BANK_SEPARATOR = "/";
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

    private final LocalDateTime time;
    private final String clientId;
    private final AuthenticationType method;
    private final StatisticsOperation operation;
    private final String errorDescription;
    private final String bank;

    private StatisticsRecord(LocalDateTime time, String clientId, AuthenticationType method, StatisticsOperation operation,
                            String errorDescription, String bank) {
        Assert.notNull(time, "Authentication time cannot be null!");
        Assert.notNull(clientId, "Client-ID cannot be null!");
        Assert.notNull(method, "Authentication method cannot be null!");
        Assert.notNull(operation, "Statistics operation cannot be null!");

        if (operation == StatisticsOperation.ERROR)
            Assert.notNull(errorDescription, "Error description cannot be null!");
        if (method == AuthenticationType.BankLink)
            Assert.notNull(bank, "Bank cannot be null!");

        this.time = time;
        this.clientId = clientId;
        this.method = method;
        this.operation = operation;
        this.errorDescription = errorDescription;
        this.bank = bank;
    }

    public StatisticsRecord(LocalDateTime time, String clientId, AuthenticationType method, StatisticsOperation operation) {
        this(time, clientId, method, operation, null, null);
    }

    public StatisticsRecord(LocalDateTime time, String clientId, AuthenticationType method, String errorDescription) {
        this(time, clientId, method, StatisticsOperation.ERROR, errorDescription != null ? errorDescription : "", null);
    }

    public StatisticsRecord(LocalDateTime time, String clientId, BankEnum bank, StatisticsOperation operation) {
        this(time, clientId, AuthenticationType.BankLink, operation, null, bank.getName());
    }

    public StatisticsRecord(LocalDateTime time, String clientId, BankEnum bank, String errorDescription) {
        this(time, clientId, AuthenticationType.BankLink, StatisticsOperation.ERROR, errorDescription != null ? errorDescription : "", bank.getName());
    }

    public String getTime() {
        return this.time.toString();
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getMethod() {
        return this.method.getAmrName();
    }

    public String getOperation() {
        return this.operation.name();
    }

    public String getError() {
        return this.errorDescription;
    }

    public String getBank() {
        return this.bank;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(formatter.format(this.time)).append(';');
        sb.append(this.clientId).append(';');

        sb.append(this.method.name());
        if (this.bank != null)
            sb.append(METHOD_BANK_SEPARATOR).append(this.bank);
        sb.append(';');

        sb.append(this.operation.name()).append(';');
        if (this.errorDescription != null)
            sb.append(this.errorDescription);

        return sb.toString();
    }

}
