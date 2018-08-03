package ee.ria.sso.flow;

import org.apereo.cas.authentication.RememberMeUsernamePasswordCredential;
import org.apereo.cas.web.flow.DefaultWebflowConfigurer;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import ee.ria.sso.authentication.credential.TaraCredential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraWebflowConfigurer extends DefaultWebflowConfigurer {

    public TaraWebflowConfigurer(FlowBuilderServices flowBuilderServices, FlowDefinitionRegistry flowDefinitionRegistry) {
        super(flowBuilderServices, flowDefinitionRegistry);
    }

    // TODO: TaraCredential is added to the flow scope here, before any authentication starts
    // TaraCredential is used to forward pre-authentication data to authentication services

    @Override
    protected void createRememberMeAuthnWebflowConfig(Flow flow) {
        if (this.casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            this.createFlowVariable(flow, "credential", RememberMeUsernamePasswordCredential.class);
            ViewState state = (ViewState)flow.getState("viewLoginForm");
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new BinderConfiguration.Binding("rememberMe", null, false));
        } else {
            this.createFlowVariable(flow, "credential", TaraCredential.class);
        }
    }

}
