package org.apereo.cas.config.support.authentication;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.util.AsciiArtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import ee.ria.sso.authentication.principal.TaraPrincipalResolver;

/**
 *
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

@Configuration("acceptUsersAuthenticationEventExecutionPlanConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class AcceptUsersAuthenticationEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {

	private static final Logger LOGGER = LoggerFactory.getLogger(AcceptUsersAuthenticationEventExecutionPlanConfiguration.class);

	@Autowired
	private TaraPrincipalResolver taraPrincipalResolver;

	@Autowired
	@Qualifier("taraAuthenticationHandler")
	private AuthenticationHandler taraAuthenticationHandler;

	@Override
	public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
		final String header = ""
				+ "-----------------------------------------------------------------------"
				+ "Authentication Execution Plan of RIIGI INFOSÜSTEEMI AMET has been loaded"
				+ "-----------------------------------------------------------------------";

		AsciiArtUtils.printAsciiArtWarning(LOGGER, "RIIGI INFOSÜSTEEMI AMET", header);
		plan.registerAuthenticationHandlerWithPrincipalResolver(this.taraAuthenticationHandler, this.taraPrincipalResolver);
	}

}
