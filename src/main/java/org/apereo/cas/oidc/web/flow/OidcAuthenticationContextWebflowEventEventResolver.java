//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.oidc.web.flow;

import java.util.*;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.services.MultifactorAuthenticationProvider;
import org.apereo.cas.services.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.web.flow.authentication.BaseMultifactorAuthenticationProviderEventResolver;
import org.apereo.cas.web.support.WebUtils;
import org.jasig.cas.client.util.URIBuilder;
import org.jasig.cas.client.util.URIBuilder.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

public class OidcAuthenticationContextWebflowEventEventResolver extends BaseMultifactorAuthenticationProviderEventResolver {
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcAuthenticationContextWebflowEventEventResolver.class);

    public OidcAuthenticationContextWebflowEventEventResolver(AuthenticationSystemSupport authenticationSystemSupport, CentralAuthenticationService centralAuthenticationService, ServicesManager servicesManager, TicketRegistrySupport ticketRegistrySupport, CookieGenerator warnCookieGenerator, AuthenticationServiceSelectionPlan authenticationSelectionStrategies, MultifactorAuthenticationProviderSelector selector) {
        super(authenticationSystemSupport, centralAuthenticationService, servicesManager, ticketRegistrySupport, warnCookieGenerator, authenticationSelectionStrategies, selector);
    }

    public Set<Event> resolveInternal(RequestContext context) {
        RegisteredService service = this.resolveRegisteredServiceInRequestContext(context);
        Authentication authentication = WebUtils.getAuthentication(context);
        HttpServletRequest request = WebUtils.getHttpServletRequest(context);
        if (service != null && authentication != null) {
            String acr = request.getParameter("acr_values");
            if (StringUtils.isBlank(acr)) {
                URIBuilder builderContext = new URIBuilder(StringUtils.trimToEmpty(context.getFlowExecutionUrl()));
                Optional<BasicNameValuePair> parameter = builderContext.getQueryParams().stream().filter((p) -> {
                    return p.getName().equals("acr_values");
                }).findFirst();
                if (parameter.isPresent()) {
                    acr = ((BasicNameValuePair)parameter.get()).getValue();
                }
            }

            if (StringUtils.isBlank(acr)) {
                LOGGER.debug("No ACR provided in the authentication request");
                return null;
            } else if (Arrays.asList("low", "substantial", "high").contains(acr)) {
                LOGGER.debug("eIDAS specific ACR value {%s} provided; bypassing CAS multifactor authentication provider check");
                return null;
            } else {
                Set<String> values = org.springframework.util.StringUtils.commaDelimitedListToSet(acr);
                if (values.isEmpty()) {
                    LOGGER.debug("No ACR provided in the authentication request");
                    return null;
                } else {
                    Map<String, MultifactorAuthenticationProvider> providerMap = WebUtils.getAvailableMultifactorAuthenticationProviders(this.applicationContext);
                    if (providerMap != null && !providerMap.isEmpty()) {
                        Collection<MultifactorAuthenticationProvider> flattenedProviders = this.flattenProviders(providerMap.values());
                        Optional<MultifactorAuthenticationProvider> provider = flattenedProviders.stream().filter((v) -> {
                            return values.contains(v.getId());
                        }).findAny();
                        if (provider.isPresent()) {
                            return Collections.singleton(new Event(this, ((MultifactorAuthenticationProvider)provider.get()).getId()));
                        } else {
                            LOGGER.warn("The requested authentication class [{}] cannot be satisfied by any of the MFA providers available", values);
                            throw new AuthenticationException();
                        }
                    } else {
                        LOGGER.error("No multifactor authentication providers are available in the application context to handle [{}]", values);
                        throw new AuthenticationException();
                    }
                }
            }
        } else {
            LOGGER.debug("No service or authentication is available to determine event for principal");
            return null;
        }
    }
}
