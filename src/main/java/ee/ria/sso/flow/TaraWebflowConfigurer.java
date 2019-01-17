package ee.ria.sso.flow;

import ee.ria.sso.authentication.credential.TaraCredential;
import org.apereo.cas.authentication.RememberMeUsernamePasswordCredential;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.configurer.DefaultLoginWebflowConfigurer;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraWebflowConfigurer extends DefaultLoginWebflowConfigurer {

    public TaraWebflowConfigurer(FlowBuilderServices flowBuilderServices, FlowDefinitionRegistry loginFlowDefinitionRegistry, ApplicationContext applicationContext, CasConfigurationProperties casProperties) {
        super(flowBuilderServices, loginFlowDefinitionRegistry, applicationContext, casProperties);
    }

    protected void doInitialize() {
        super.doInitialize();
        getLoginFlow().setStartState("handleCallbackResultOrStartNewAuthenticationProcess");
    }

    @Override
    protected void createRememberMeAuthnWebflowConfig(Flow flow) {
        if (this.casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            this.createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, RememberMeUsernamePasswordCredential.class);
            ViewState state = (ViewState) flow.getState("viewLoginForm");
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new BinderConfiguration.Binding("rememberMe", null, false));
        } else {
            this.createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, TaraCredential.class);
        }
    }

    // TODO: TaraCredential is added to the flow scope here, before any authentication starts
    // TaraCredential is used to forward pre-authentication data to authentication services

}
