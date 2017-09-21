package org.apereo.cas.web.flow.resolver.impl;

import java.util.Set;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.AuthenticationContextValidator;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.services.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;


/**
 * Created by serkp on 21.09.2017.
 */

public class RankedAuthenticationProviderWebflowEventResolver extends AbstractCasWebflowEventResolver {
	private static final Logger LOGGER = LoggerFactory.getLogger(RankedAuthenticationProviderWebflowEventResolver.class);

	public RankedAuthenticationProviderWebflowEventResolver(AuthenticationSystemSupport authenticationSystemSupport, CentralAuthenticationService centralAuthenticationService, ServicesManager servicesManager, TicketRegistrySupport ticketRegistrySupport, CookieGenerator warnCookieGenerator, AuthenticationServiceSelectionPlan authenticationSelectionStrategies, MultifactorAuthenticationProviderSelector selector, AuthenticationContextValidator authenticationContextValidator, CasDelegatingWebflowEventResolver casDelegatingWebflowEventResolver) {
		super(authenticationSystemSupport, centralAuthenticationService, servicesManager, ticketRegistrySupport, warnCookieGenerator, authenticationSelectionStrategies, selector);
	}

	public Set<Event> resolveInternal(RequestContext context) {
		RegisteredService service = WebUtils.getRegisteredService(context);
		if(service == null) {
			throw new RuntimeException("Autentimisteenuse üldine viga või keelatud tegevus");
		} else {
			return this.resumeFlow();
		}
	}

	@Audit(
			action = "AUTHENTICATION_EVENT",
			actionResolverName = "AUTHENTICATION_EVENT_ACTION_RESOLVER",
			resourceResolverName = "AUTHENTICATION_EVENT_RESOURCE_RESOLVER"
	)
	public Event resolveSingle(RequestContext context) {
		return super.resolveSingle(context);
	}

	private Set<Event> resumeFlow() {
		return CollectionUtils.wrapSet((new EventFactorySupport()).success(this));
	}
}
