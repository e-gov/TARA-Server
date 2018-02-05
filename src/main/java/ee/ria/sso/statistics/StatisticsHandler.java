package ee.ria.sso.statistics;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.webflow.execution.RequestContext;

import ee.ria.sso.authentication.AuthenticationType;

/**
 * Created by serkp on 08.12.2017.
 */

@Component
public class StatisticsHandler {

    private final Logger log = LoggerFactory.getLogger(StatisticsHandler.class);
    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

    public void collect(LocalDateTime time, RequestContext context, AuthenticationType authenticationType,
                        StatisticsOperation operationCode) {
        this.collect(time, (HttpServletRequest) context.getExternalContext().getNativeRequest(), authenticationType,
            operationCode);
    }

    public void collect(LocalDateTime time, HttpServletRequest request, AuthenticationType authenticationType,
                        StatisticsOperation operationCode) {
        Assert.isTrue(!Arrays.asList(StatisticsOperation.ERROR).contains(operationCode), "Illegal operation code");
        this.collect(time, request, authenticationType, operationCode, "");
    }

    public void collect(LocalDateTime time, RequestContext context, AuthenticationType authenticationType,
                        StatisticsOperation operationCode, String causeOfError) {
        this.collect(time, (HttpServletRequest) context.getExternalContext().getNativeRequest(), authenticationType,
            operationCode, causeOfError);
    }

    public void collect(LocalDateTime time, HttpServletRequest request, AuthenticationType authenticationType,
                        StatisticsOperation operationCode, String causeOfError) {
        Optional<String> clientId = this.getClientId(request);
        if (clientId.isPresent()) {
            this.log.info(String.format("%s;%s;%s;%s;%s", this.formatter.format(time), clientId.get(), authenticationType,
                operationCode, causeOfError));
        }
    }

    /*
     * RESTRICTED METHODS
     */

    private Optional<String> getClientId(HttpServletRequest request) {
        String serviceParameter = request.getParameter("service");
        if (StringUtils.isNotBlank(serviceParameter)) {
            UriComponents serviceUri = UriComponentsBuilder.fromUriString(serviceParameter).build();
            try {
                return Optional.of(serviceUri.getQueryParams().get("client_id").get(0));
            } catch (Exception ignore) {
            }
        }
        return Optional.empty();
    }

}
