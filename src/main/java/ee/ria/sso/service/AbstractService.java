package ee.ria.sso.service;

import ee.ria.sso.Constants;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.util.EncodingUtils;
import org.springframework.webflow.core.collection.SharedAttributeMap;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Slf4j
public class AbstractService {

    private final TaraResourceBundleMessageSource messageSource;

    public AbstractService(TaraResourceBundleMessageSource messageSource) {
        this.messageSource = messageSource;
    }

    protected SharedAttributeMap<Object> getSessionMap(RequestContext context) {
        return context.getExternalContext().getSessionMap();
    }

    protected String getServiceClientId(RequestContext context) {
        final Object attribute = context.getExternalContext().getSessionMap()
                .get(Constants.TARA_OIDC_SESSION_CLIENT_ID);

        if (attribute != null && attribute instanceof String)
            return (String) attribute;

        String serviceParameter = ((HttpServletRequest) context.getExternalContext().getNativeRequest())
                .getParameter(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        if (StringUtils.isBlank(serviceParameter))
            serviceParameter = getServiceUrlFromFlowContext(context);

        if (StringUtils.isNotEmpty(serviceParameter))
            serviceParameter = EncodingUtils.urlEncode(serviceParameter);

        return serviceParameter;
    }

    private String getServiceUrlFromFlowContext(RequestContext context) {
        Object attribute = context.getFlowScope().get(Constants.CAS_SERVICE_ATTRIBUTE_NAME);
        if (attribute != null && attribute instanceof WebApplicationService) {
            return ((WebApplicationService) attribute).getOriginalUrl();
        } else {
            return null;
        }
    }

    protected String getMessage(String key) {
        return messageSource.getMessage(key);
    }

    protected String getMessage(String key, String defaultMessageKey) {
        return messageSource.getMessage(key, defaultMessageKey);
    }

    protected String getMessage(String key, String defaultMessageKey, Object... parameters) {
        return messageSource.getMessage(key, defaultMessageKey, parameters);
    }

}
