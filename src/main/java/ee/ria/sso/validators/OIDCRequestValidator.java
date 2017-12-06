package ee.ria.sso.validators;

import java.util.List;
import java.util.Optional;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.J2EContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class OIDCRequestValidator {

    private static final Logger log = LoggerFactory.getLogger(OIDCRequestValidator.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    public enum RequestParameter {

        CLIENT_ID("invalid_client"), SCOPE("invalid_scope"), STATE("invalid_request"), REDIRECT_URI("invalid_request"),
        RESPONSE_TYPE("invalid_request");

        private String error;

        RequestParameter(String error) {
            this.error = error;
        }

        public String getError() {
            return error;
        }

    }

    public static Optional<Integer> validateAll(final J2EContext context, final List<RequestParameter> parameters) {
        if (CollectionUtils.isNotEmpty(parameters)) {
            for (RequestParameter parameter : parameters) {
                Optional<Integer> r = validate(context, parameter);
                if (r.isPresent()) {
                    return r;
                }
            }
        }
        return Optional.empty();
    }

    public static Optional<Integer> validate(final J2EContext context, final RequestParameter parameter) {
        try {
            String parameterKey = parameter.name().toLowerCase();
            String parameterValue = context.getRequestParameter(parameterKey);
            if (StringUtils.isBlank(parameterValue)) {
                log.warn("No request parameter <{}> provided", parameterKey);
                context.writeResponseContent(mapper.writeValueAsString(new ErrorResponse(parameter.getError())));
                context.setResponseContentType("application/json");
                context.setResponseStatus(400);
                return Optional.of(400);
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.error("Error while validating OIDC request", e);
            } else {
                log.error("Error while validating OIDC request: {}", e.getMessage());
            }
            context.setResponseStatus(500);
            return Optional.of(500);
        }
        return Optional.empty();
    }

}
