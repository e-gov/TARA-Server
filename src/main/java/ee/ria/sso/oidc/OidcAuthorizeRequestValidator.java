package ee.ria.sso.oidc;

import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.flow.JSONFlowExecutionException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Slf4j
@Component
public class OidcAuthorizeRequestValidator {

    @Autowired
    private ServicesManager servicesManager;

    public static void checkGrantType(HttpServletRequest request) {
        Optional<String> grantType = Optional.ofNullable(request.getParameter("grant_type"));
        if (grantType.isPresent()) {
            if (!OAuth20GrantTypes.AUTHORIZATION_CODE.getType().equals(grantType.get())) {
                throw JSONFlowExecutionException.ofBadRequest(Collections.singletonMap("error", "unsupported_grant_type"),
                        new RuntimeException("Unsupported grant type"));
            }
        } else {
            throw JSONFlowExecutionException.ofBadRequest(Collections.singletonMap("error", "invalid_request"),
                    new RuntimeException("No grant type found"));
        }
    }

    public void validateAuthenticationRequestParameters(final HttpServletRequest request) {

        validateRedirectUriIsRegistered(request);

        for (OidcAuthorizeRequestParameter parameter : Arrays.asList(OidcAuthorizeRequestParameter.values())) {
            validateParameter(request, parameter);

            switch (parameter) {
                case SCOPE:
                    validateScopeValue(request);
                    break;
                case RESPONSE_TYPE:
                    validateResponseType(request);
                    break;
                case ACR_VALUES:
                    validateAcrValues(request);
                    break;
                default:
                    break;
            }
        }
    }

    private static void validateParameter(HttpServletRequest request, OidcAuthorizeRequestParameter parameter) {
        assertParameterValueNotEmpty(request, parameter);
        assertParameterHasSingleValue(request, parameter);
    }

    private String validateRedirectUriIsRegistered(HttpServletRequest request) {
        Assert.notNull(servicesManager, "Services manager could not be found!");
        validateParameter(request, OidcAuthorizeRequestParameter.CLIENT_ID);

        String clientId = request.getParameter(OidcAuthorizeRequestParameter.CLIENT_ID.getParameterKey());
        OAuthRegisteredService registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(servicesManager, clientId);
        if (registeredService != null && registeredService.getAccessStrategy().isServiceAccessAllowed()) {
            String urlPattern = registeredService.getServiceId();
            String redirectUrl = request.getParameter(OidcAuthorizeRequestParameter.REDIRECT_URI.getParameterKey());
            if (redirectUrl != null && redirectUrl.matches(urlPattern)) {
                return redirectUrl;
            } else {
                throw new InvalidRequestException(OidcAuthorizeRequestParameter.REDIRECT_URI, "invalid_request",
                        String.format("redirect_uri does not match the registration! Url to match: '%s', url from client: '%s'", urlPattern, redirectUrl));
            }
        } else {
            throw new InvalidRequestException(OidcAuthorizeRequestParameter.REDIRECT_URI, "invalid_request",
                    String.format("Unauthorized client with client_id: '%s'. Either the client_id was never registered or it's access has been disabled.", clientId));
        }
    }

    private static void assertParameterHasSingleValue(final HttpServletRequest request, final OidcAuthorizeRequestParameter parameter) {

        String[] values = request.getParameterValues(parameter.getParameterKey());
        if (values != null && values.length > 1) {
            throw new InvalidRequestException(parameter, "invalid_request",
                    String.format("Multiple values found in the request for <%s> parameter", parameter.getParameterKey()));
        }
    }

    private static void assertParameterValueNotEmpty(final HttpServletRequest request, final OidcAuthorizeRequestParameter parameter) {
        String parameterValue = request.getParameter(parameter.getParameterKey());
        boolean isValueMandatory = parameter.isMandatory() || request.getParameterMap().containsKey(parameter.getParameterKey());
        if (StringUtils.isBlank(parameterValue) && isValueMandatory) {
            throw new InvalidRequestException(parameter, parameter.getError(),
                    String.format("No value found in the request for <%s> parameter", parameter.getParameterKey()));
        }
    }

    private static void validateScopeValue(final HttpServletRequest request) {
        String scope = request.getParameter(OidcAuthorizeRequestParameter.SCOPE.getParameterKey());
        List scopes = Arrays.stream(scope.split(" ")).collect(Collectors.toList());

        if (scopes.isEmpty() || !scopes.contains(TaraScope.OPENID.getFormalName())) {
            throw new InvalidRequestException(OidcAuthorizeRequestParameter.SCOPE, "invalid_scope", String.format(
                    "Required scope <%s> not provided. TARA do not allow this request to be processed",
                    TaraScope.OPENID.getFormalName()
            ));
        }

        List<String> allowedScopes = Stream.of(TaraScope.values()).map(TaraScope::getFormalName).collect(Collectors.toList());
        if (!ListUtils.subtract(scopes, allowedScopes).isEmpty()) {
            throw new InvalidRequestException(OidcAuthorizeRequestParameter.SCOPE, "invalid_scope", String.format(
                    "One or some of the provided scopes are not allowed by TARA, only <%s> are permitted. TARA do not allow this request to be processed",
                    allowedScopes.stream().collect(Collectors.joining(", "))
            ));
        }
    }

    private static void validateResponseType(final HttpServletRequest request) {
        String responseType = request.getParameter(OidcAuthorizeRequestParameter.RESPONSE_TYPE.getParameterKey());
        if (!"code".equals(responseType)) {
            throw new InvalidRequestException(OidcAuthorizeRequestParameter.RESPONSE_TYPE, "unsupported_response_type", String.format(
                    "Provided response type is not allowed by TARA, only <%s> is permitted. TARA do not allow this request to be processed", "code"
            ));
        }
    }

    private static void validateAcrValues(final HttpServletRequest request) {
        String acrValues = request.getParameter(OidcAuthorizeRequestParameter.ACR_VALUES.getParameterKey());

        if (acrValues != null) {
            final List<String> allowedValues = Stream.of(LevelOfAssurance.values())
                    .map(LevelOfAssurance::getAcrName).collect(Collectors.toList());

            if (!allowedValues.contains(acrValues)) {
                throw new InvalidRequestException(OidcAuthorizeRequestParameter.ACR_VALUES, "unsupported_acr_values", String.format(
                        "Provided acr_values is not allowed by TARA, only <%s> are permitted. TARA do not allow this request to be processed",
                        allowedValues.stream().collect(Collectors.joining(", ")
                        )));
            }
        }
    }

    public static class InvalidRequestException extends RuntimeException {

        private final OidcAuthorizeRequestParameter parameter;
        private final String errorCode;
        private final String errorDescription;

        public InvalidRequestException(OidcAuthorizeRequestParameter parameter, String errorCode, String errorDescription) {
            super(errorDescription);
            this.parameter = parameter;
            this.errorCode = errorCode;
            this.errorDescription = errorDescription;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public String getErrorDescription() {
            return errorDescription;
        }

        public OidcAuthorizeRequestParameter getInvalidParameter() {
            return parameter;
        }
    }
}
