package ee.ria.sso.statistics;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.execution.RequestContext;


/**
 * Created by serkp on 08.12.2017.
 */

@Component
public class StatisticsWrapper {

    private static final Logger log = LoggerFactory.getLogger(StatisticsWrapper.class);

    public void logStatisticsAction(String toiminguAeg, RequestContext context, StatAuthTypeEnum
            autentimisMeetod, StatOperationCode toiminguTulemus, String ebaeduPohjus) {
        String separator = ";";
        String clientId = UriComponentsBuilder.fromUriString(context.getExternalContext()
                                                                    .getRequestParameterMap()
                                                                    .get("service")).build()
                                              .getQueryParams().get("client_id").get(0);
        log.info(toiminguAeg + separator + clientId + separator + autentimisMeetod + separator
                         + toiminguTulemus + separator + ebaeduPohjus);
    }

}
