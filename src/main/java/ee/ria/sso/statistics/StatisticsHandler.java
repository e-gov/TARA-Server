package ee.ria.sso.statistics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * Created by serkp on 08.12.2017.
 */

@Component
public class StatisticsHandler {

    private final Logger log = LoggerFactory.getLogger(StatisticsHandler.class);

    @Autowired(required=false)
    private TaraStatHandler taraStatHandler;

    public void collect(StatisticsRecord statisticsRecord) {
        Assert.notNull(statisticsRecord, "StatisticsRecord cannot be null!");
        this.log.info(statisticsRecord.toString());

        if (this.taraStatHandler != null)
            this.taraStatHandler.collect(statisticsRecord);
    }

}
