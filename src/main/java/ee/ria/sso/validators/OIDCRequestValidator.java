package ee.ria.sso.validators;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.pac4j.core.context.J2EContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class OIDCRequestValidator {

    private static final Logger log = LoggerFactory.getLogger(OIDCRequestValidator.class);

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
                return resultOfBadRequest(ErrorResponse.of(context, parameter.getError(),
                    String.format("No value for request parameter <%s> provided", parameterKey)));
            }
            Optional<Integer> code;
            switch (parameter) {
                case SCOPE:
                    code = validateScopeValue(context);
                    break;
                case RESPONSE_TYPE:
                    code = validateResponseType(context);
                    break;
                default:
                    code = Optional.empty();
            }
            return code;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.error("Error while validating OIDC request", e);
            } else {
                log.error("Error while validating OIDC request: {}", e.getMessage());
            }
            return resultOfInternalServerError(ErrorResponse.of(context, "server_error"));
        }
    }

    private static Optional<Integer> validateScopeValue(final J2EContext context) throws Exception {
        String scope = context.getRequestParameter(RequestParameter.SCOPE.name().toLowerCase());
        if (!"openid".equals(scope)) {
            return resultOfBadRequest(ErrorResponse.of(context, "invalid_scope",
                String.format("Provided scope <%s> is not allowed by TARA, only <%s> is permitted. TARA do not allow this request to be processed", scope, "openid")));
        }
        return Optional.empty();
    }

    private static Optional<Integer> validateResponseType(final J2EContext context) {
        String responseType = context.getRequestParameter(RequestParameter.RESPONSE_TYPE.name().toLowerCase());
        if (!"code".equals(responseType)) {
            return resultOfBadRequest(ErrorResponse.of(context, "unsupported_response_type",
                String.format("Provided response type <%s> is not allowed by TARA, only <%s> is permitted. TARA do not allow this request to be processed", responseType, "code")));
        }
        return Optional.empty();
    }

    private static Optional<Integer> resultOfInternalServerError(final ErrorResponse response) {
        return resultOf(response, Optional.of(500));
    }

    private static Optional<Integer> resultOfBadRequest(final ErrorResponse response) {
        return resultOf(response, Optional.of(400));
    }

    private static Optional<Integer> resultOf(final ErrorResponse response, Optional<Integer> optional) {
        if (response.hasErrorDescription()) {
            log.error(response.getErrorDescription());
        }
        if (response.isValidRedirectURI()) {
            if (!response.sendRedirect()) {
                return Optional.of(500);
            }
        }
        return optional;
    }

}
