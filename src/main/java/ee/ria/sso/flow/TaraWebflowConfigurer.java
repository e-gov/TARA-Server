package ee.ria.sso.flow;

import org.apereo.cas.authentication.RememberMeUsernamePasswordCredential;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.web.flow.DefaultWebflowConfigurer;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import ee.ria.sso.authentication.credential.DefaultCredential;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraWebflowConfigurer extends DefaultWebflowConfigurer {

    public TaraWebflowConfigurer(FlowBuilderServices flowBuilderServices, FlowDefinitionRegistry flowDefinitionRegistry) {
        super(flowBuilderServices, flowDefinitionRegistry);
    }

    @Override
    protected void createRememberMeAuthnWebflowConfig(Flow flow) {
        if (this.casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            this.createFlowVariable(flow, "credential", RememberMeUsernamePasswordCredential.class);
            ViewState state = (ViewState)flow.getState("viewLoginForm");
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new BinderConfiguration.Binding("rememberMe", (String)null, false));
        } else {
            this.createFlowVariable(flow, "credential", DefaultCredential.class);
        }
    }

}
