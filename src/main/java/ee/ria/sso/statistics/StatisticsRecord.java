package ee.ria.sso.statistics;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import ee.ria.sso.authentication.AuthenticationType;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Builder
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"time","clientId","method","bank","operation","error"})
public class StatisticsRecord {
    private static final String SEPARATOR = "/";
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

    private final LocalDateTime time;
    private final String clientId;
    private final AuthenticationType method;
    private final StatisticsOperation operation;
    private final String error;
    private final String bank;
    private final String country;

    public StatisticsRecord(LocalDateTime time, String clientId, AuthenticationType method, StatisticsOperation operation, String error, String bank, String country) {
        Assert.notNull(time, "Authentication time cannot be null!");
        Assert.notNull(clientId, "Client-ID cannot be null!");
        Assert.notNull(method, "Authentication method cannot be null!");
        Assert.notNull(operation, "Statistics operation cannot be null!");

        if (method == AuthenticationType.BankLink) {
            Assert.notNull(bank, "Bank cannot be null!");
        } else if (method == AuthenticationType.eIDAS)
            Assert.notNull(country, "Country cannot be null!");

        this.time = time;
        this.clientId = clientId;
        this.method = method;
        this.operation = operation;
        this.error = error;
        this.bank = bank;
        this.country = country;
    }

    public String getTime() {
        return this.time.toString();
    }

    public String getOperation() {
        return this.operation.name();
    }

    public String getMethod() {
        return this.method.getAmrName();
    }

    public String getBank() {
        return bank != null ? bank.toUpperCase() : null;
    }

    public String getCountry() {
        return country != null ? country.toUpperCase() : null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(formatter.format(this.time)).append(';');
        sb.append(this.clientId).append(';');

        sb.append(this.method.name());
        if (this.bank != null) {
            sb.append(SEPARATOR).append(this.getBank());
        } else if (this.country != null) {
            sb.append(SEPARATOR).append(this.getCountry());
        }
        sb.append(';');

        sb.append(this.operation.name()).append(';');
        if (this.error != null)
            sb.append(this.error);

        return sb.toString();
    }
}
