package ee.ria.sso.statistics;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.sso.authentication.AuthenticationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@ConditionalOnProperty("statistics.tara-stat.enabled")
public class TaraStatHandler {

    private static final String MESSAGE_KEY_TIME = "time";
    private static final String MESSAGE_KEY_CLIENT_ID = "clientId";
    private static final String MESSAGE_KEY_AUTH_METHOD = "method";
    private static final String MESSAGE_KEY_STAT_OPERATION = "operation";
    private static final String MESSAGE_KEY_CAUSE_OF_ERROR = "error";

    private Logger log = LoggerFactory.getLogger(TaraStatHandler.class);

    public void collect(LocalDateTime time, String clientId, AuthenticationType authenticationType, StatisticsOperation operationCode, String causeOfError) {
        Map<String,String> message = new LinkedHashMap<>();
        message.put(MESSAGE_KEY_TIME, time.toString());
        message.put(MESSAGE_KEY_CLIENT_ID, clientId);
        message.put(MESSAGE_KEY_AUTH_METHOD, authenticationType.getAmrName());
        message.put(MESSAGE_KEY_STAT_OPERATION, operationCode.name());

        if (operationCode == StatisticsOperation.ERROR)
            message.put(MESSAGE_KEY_CAUSE_OF_ERROR, causeOfError);

        log.info(convertMapToJson(message));
    }

    private String convertMapToJson(Map<String,String> map) {
        try {
            return new ObjectMapper().writeValueAsString(map);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
