package ee.ria.sso.statistics;

import ee.ria.sso.authentication.AuthenticationType;
import org.hamcrest.Matcher;
import org.mockito.ArgumentMatcher;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;

public class StatisticsRecordMatcher extends ArgumentMatcher<StatisticsRecord> {

    private final Matcher<LocalDateTime> timeMatcher;
    private final Matcher<String> clientIdMatcher;
    private final Matcher<AuthenticationType> methodMatcher;
    private final Matcher<StatisticsOperation> operationMatcher;
    private final Matcher<String> errorDescriptionMatcher;
    private final Matcher<String> bankMatcher;

    public StatisticsRecordMatcher(Matcher<LocalDateTime> timeMatcher,
                                   Matcher<String> clientIdMatcher,
                                   Matcher<AuthenticationType> methodMatcher,
                                   Matcher<StatisticsOperation> operationMatcher,
                                   Matcher<String> errorDescriptionMatcher,
                                   Matcher<String> bankMatcher) {
        this.timeMatcher = timeMatcher;
        this.clientIdMatcher = clientIdMatcher;
        this.methodMatcher = methodMatcher;
        this.operationMatcher = operationMatcher;
        this.errorDescriptionMatcher = errorDescriptionMatcher;
        this.bankMatcher = bankMatcher;
    }

    @Override
    public boolean matches(Object actual) {
        if (!StatisticsRecord.class.isInstance(actual))
            return false;

        StatisticsRecord statisticsRecord = (StatisticsRecord) actual;
        return timeMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "time")) &&
                clientIdMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "clientId")) &&
                methodMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "method")) &&
                operationMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "operation")) &&
                errorDescriptionMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "errorDescription")) &&
                bankMatcher.matches(ReflectionTestUtils.getField(statisticsRecord, "bank"));
    }

}
