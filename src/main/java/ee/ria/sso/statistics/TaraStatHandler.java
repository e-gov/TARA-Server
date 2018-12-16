package ee.ria.sso.statistics;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@ConditionalOnProperty("statistics.tara-stat.enabled")
public class TaraStatHandler {

    private Logger log = LoggerFactory.getLogger(TaraStatHandler.class);

    public void collect(StatisticsRecord statisticsRecord) {
        Assert.notNull(statisticsRecord, "StatisticsRecord cannot be null!");

        try {
            log.info(new ObjectMapper().writeValueAsString(statisticsRecord));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

}
